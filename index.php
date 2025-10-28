<?php
// SendFile - hardened index.php
// Changes:
// - Validate and sanitize IDs and client-supplied path segments
// - Locking around chunk finalize to prevent races (flock)
// - Magic-byte checks for ZIP/RAR in addition to finfo
// - Atomic JSON writes for metadata
// - Realpath containment checks for all filesystem operations
// - Safer file permissions (0600 for stored files), safer Content-Disposition
// - Optional Apache X-Sendfile support (enable below)
// - Security HTTP headers when serving files/archives
//
// Note: UI (HTML/CSS/JS) is preserved with minimal changes. Test in staging before production.

const BASE_URL = '';
const UPLOAD_DIR = __DIR__ . '/uploads';
const DATA_DIR = __DIR__ . '/data';
const TMP_DIR = __DIR__ . '/tmp_chunks';
const SHARE_ID_LEN = 16; // hex chars
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 2 TB (keep in mind PHP/FS limits)
const CHUNK_SIZE = 20 * 1024 * 1024; // 20 MB
const SHARE_TTL_DAYS = 2;

// If you enable Apache mod_xsendfile, set to true and configure Apache accordingly.
// When true, serve_file() will send "X-Sendfile: /abs/path" header instead of readfile().
// Requires mod_xsendfile (or equivalent) on your Apache server.
const ENABLE_X_SENDFILE = true;

umask(0022);

if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);
if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0755, true);
if (!is_dir(TMP_DIR)) mkdir(TMP_DIR, 0755, true);

function get_random_bg_image() {
    $sources = [
        "https://picsum.photos/1920/1080"
    ];
    return $sources[array_rand($sources)];
}

// ------------------ Helpers ------------------

function base_url(){
    if (BASE_URL !== '') return rtrim(BASE_URL, '/');
    $s = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? '');
    // basic sanitization of Host header (strip control chars)
    $host = preg_replace('/[^A-Za-z0-9\.\:\-]/', '', $host);
    $s .= '://' . $host;
    $s .= rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
    return rtrim($s, '/');
}

function gen_id($len=16){
    if ($len % 2 !== 0) $len++;
    return bin2hex(random_bytes($len/2));
}

function is_valid_share_id($id){
    return is_string($id) && preg_match('/^[a-f0-9]{'.SHARE_ID_LEN.'}$/', $id);
}

function sanitize_chunk_id($id){
    if (!is_string($id)) return '';
    $s = preg_replace('/[^A-Za-z0-9_\-]/', '', $id);
    return substr($s, 0, 64);
}

function sanitize_filename($name){
    $name = trim($name);
    $name = preg_replace('/[\\\\\/]+/', '_', $name); // remove directory separators
    $name = preg_replace('/[^A-Za-z0-9_\.\-\(\) ]+/', '', $name);
    $name = substr($name, 0, 255);
    $name = ltrim($name, '.');
    if (!$name) $name = gen_id(8) . ".file";
    return $name;
}

function limit_sender($s){
    $s = trim($s);
    if ($s === '') return '';
    $s = substr($s, 0, 128);
    return htmlspecialchars($s, ENT_QUOTES|ENT_HTML5);
}

function atomic_file_put_contents($path, $data){
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $data, LOCK_EX) === false) return false;
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

function json_save($id, $data){
    $dir = DATA_DIR;
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $fname = $dir . "/$id.json";
    $json = json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    if ($json === false) return false;
    if (!atomic_file_put_contents($fname, $json)) return false;
    @chmod($fname, 0644);
    return true;
}
function json_load($id){
    if (!is_valid_share_id($id)) return null;
    $f = DATA_DIR . "/$id.json";
    if (!file_exists($f)) return null;
    $contents = file_get_contents($f);
    if ($contents === false) return null;
    return json_decode($contents, true);
}

function is_inside_dir($base, $path){
    $realBase = realpath($base);
    $realPath = realpath($path);
    if ($realBase === false || $realPath === false) return false;
    return strpos($realPath, $realBase) === 0;
}

// Returns 'zip'|'rar'|false
function detect_archive_magic($path){
    if (!is_readable($path)) return false;
    $fh = fopen($path, 'rb');
    if (!$fh) return false;
    $bytes = fread($fh, 8);
    fclose($fh);
    if ($bytes === false) return false;
    if (strncmp($bytes, "PK\x03\x04", 4) === 0 || strncmp($bytes, "PK\x05\x06", 4) === 0 || strncmp($bytes, "PK\x07\x08", 4) === 0) return 'zip';
    if (strncmp($bytes, "Rar!\x1A\x07\x00", 7) === 0 || strncmp($bytes, "Rar!\x1A\x07\x01\x00", 8) === 0) return 'rar';
    return false;
}

function is_allowed_filetype($filename, $tmp_path) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, ['zip', 'rar'])) return false;
    $magic = detect_archive_magic($tmp_path);
    if ($magic === false) return false;
    if ($ext === 'zip' && $magic !== 'zip') return false;
    if ($ext === 'rar' && $magic !== 'rar') return false;
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $tmp_path);
        finfo_close($finfo);
        $allowed = [
            'zip' => ['application/zip','application/x-zip-compressed','application/octet-stream'],
            'rar' => ['application/x-rar','application/x-rar-compressed','application/octet-stream']
        ];
        if (!in_array($mime, $allowed[$ext])) return false;
    }
    return true;
}

// ------------------ Share management ------------------

function make_share($files, $sender_name=''){
    $id = gen_id(SHARE_ID_LEN);
    $dir = UPLOAD_DIR . "/$id";
    if (!mkdir($dir, 0755, true)) return [false, "Failed to create share directory"];
    $meta = [
        'id'=>$id,
        'created'=>time(),
        'expires'=>time() + SHARE_TTL_DAYS*86400,
        'files'=>[],
        'sender'=> limit_sender($sender_name),
    ];
    foreach($files as $f){
        $orig = isset($f['name']) ? sanitize_filename($f['name']) : gen_id(8).".file";
        $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
        $stored = gen_id(32) . ($ext ? ".".$ext : "");
        $target = $dir . '/' . $stored;
        $tries = 0;
        while (file_exists($target) && $tries < 5) {
            $stored = gen_id(32) . ($ext ? ".".$ext : "");
            $target = $dir . '/' . $stored;
            $tries++;
        }
        if (!isset($f['tmp_name']) || !file_exists($f['tmp_name'])) return [false, "Uploaded file missing"];
        // prefer atomic rename
        if (!rename($f['tmp_name'], $target)) {
            if (!copy($f['tmp_name'], $target) || !unlink($f['tmp_name'])) {
                return [false, "Failed to move uploaded file"];
            }
        }
        @chmod($target, 0600);
        $meta['files'][] = [
            'name' => htmlspecialchars($orig, ENT_QUOTES|ENT_HTML5),
            'stored' => $stored,
            'size' => filesize($target)
        ];
    }
    if (!json_save($id, $meta)) return [false, "Failed to save metadata"];
    return [true, $id];
}

function serve_file($share, $file){
    if (!is_valid_share_id($share)) { http_response_code(404); exit('Share not found'); }
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); exit('Share not found'); }
    $found = null;
    foreach ($meta['files'] as $f) {
        if ($f['stored'] === $file || $f['name'] === $file) { $found = $f; break; }
    }
    if (!$found) { http_response_code(404); exit('File not found'); }

    $path = UPLOAD_DIR . "/$share/" . $found['stored'];
    if (!is_inside_dir(UPLOAD_DIR, $path) || !file_exists($path)) { http_response_code(404); exit('File not found'); }

    // security headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    if (!headers_sent()) header('Content-Security-Policy: default-src \'none\'');

    $safeName = str_replace(['"', "\n", "\r"], '', basename($found['name']));
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.$safeName.'"');
    header('Content-Length: '.filesize($path));

    if (ENABLE_X_SENDFILE) {
        // rely on webserver to serve the file (Apache mod_xsendfile)
        header('X-Sendfile: ' . $path);
        // end response
        exit;
    } else {
        readfile($path);
        exit;
    }
}

function serve_zip($share){
    if (!is_valid_share_id($share)) { http_response_code(404); exit('Share not found'); }
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); exit('Share not found'); }
    $dir = UPLOAD_DIR . "/$share";
    if (!class_exists('ZipArchive')) { http_response_code(500); exit('ZIP not available'); }
    $zipname = tempnam(sys_get_temp_dir(), 'zip');
    $zip = new ZipArchive();
    if ($zip->open($zipname, ZipArchive::CREATE | ZipArchive::OVERWRITE)!==TRUE) exit('Could not create zip');
    foreach($meta['files'] as $f){
        $filepath = $dir.'/'.$f['stored'];
        if (!is_inside_dir(UPLOAD_DIR, $filepath)) {
            error_log("Invalid path for zip: $filepath");
            continue;
        }
        if (!file_exists($filepath) || filesize($filepath) === 0) {
            error_log("File missing or empty for ZIP: $filepath");
            continue;
        }
        $inName = basename($f['name']);
        $inName = str_replace(array("\0"), '', $inName);
        $zip->addFile($filepath, $inName);
    }
    $zip->close();

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="'. $share .'.zip"');
    header('Content-Length: '.filesize($zipname));
    readfile($zipname);
    unlink($zipname);
    exit;
}

// ------------------ CHUNKED UPLOAD API ------------------

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action']==='upload_chunk') {
    $file_id_raw = $_POST['file_id'] ?? '';
    $file_id = sanitize_chunk_id($file_id_raw);
    $chunk_index = isset($_POST['chunk_index']) ? intval($_POST['chunk_index']) : null;
    $total_chunks = isset($_POST['total_chunks']) ? intval($_POST['total_chunks']) : null;
    $file_name = $_POST['file_name'] ?? '';
    $sender = $_POST['sender'] ?? '';

    if (!$file_id || $chunk_index===null || $total_chunks===null || !$file_name) {
        echo json_encode(['ok'=>false,'error'=>'Missing parameters']); exit;
    }
    if (!isset($_FILES['chunk']) || $_FILES['chunk']['error']!==UPLOAD_ERR_OK) {
        echo json_encode(['ok'=>false,'error'=>'Chunk upload error']); exit;
    }
    // basic sanity checks
    if ($total_chunks < 1 || $total_chunks > 100000) { echo json_encode(['ok'=>false,'error'=>'Invalid total_chunks']); exit; }
    if ($chunk_index < 0 || $chunk_index >= $total_chunks) { echo json_encode(['ok'=>false,'error'=>'Invalid chunk_index']); exit; }

    $chunk_dir = TMP_DIR . "/$file_id";
    if (!is_dir($chunk_dir)) mkdir($chunk_dir, 0755, true);

    // save chunk safely
    $chunk_path = $chunk_dir . "/chunk_$chunk_index";
    if (!move_uploaded_file($_FILES['chunk']['tmp_name'], $chunk_path)) {
        echo json_encode(['ok'=>false,'error'=>'Failed to save chunk']); exit;
    }
    @chmod($chunk_path, 0600);
    echo json_encode(['ok'=>true,'received'=>$chunk_index]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action']==='finalize') {
    $file_id = sanitize_chunk_id($_POST['file_id'] ?? '');
    $total_chunks = isset($_POST['total_chunks']) ? intval($_POST['total_chunks']) : null;
    $file_name = $_POST['file_name'] ?? '';
    $sender = $_POST['sender'] ?? '';

    if (!$file_id || $total_chunks===null || !$file_name) {
        echo json_encode(['ok'=>false,'error'=>'Missing finalize parameters']); exit;
    }
    if ($total_chunks < 1 || $total_chunks > 100000) { echo json_encode(['ok'=>false,'error'=>'Invalid total_chunks']); exit; }

    $chunk_dir = TMP_DIR . "/$file_id";
    if (!is_dir($chunk_dir)) { echo json_encode(['ok'=>false,'error'=>'Chunks not found']); exit; }

    $lockFile = $chunk_dir . '/.lock';
    $lockFp = fopen($lockFile, 'c');
    if (!$lockFp) { echo json_encode(['ok'=>false,'error'=>'Lock error']); exit; }
    if (!flock($lockFp, LOCK_EX)) { fclose($lockFp); echo json_encode(['ok'=>false,'error'=>'Lock timeout']); exit; }

    $final_path = $chunk_dir . "/final";
    $out = fopen($final_path, 'wb');
    if (!$out) { flock($lockFp, LOCK_UN); fclose($lockFp); echo json_encode(['ok'=>false,'error'=>'Failed to open output']); exit; }

    for ($i=0; $i<$total_chunks; $i++) {
        $chunk_file = $chunk_dir . "/chunk_$i";
        if (!file_exists($chunk_file)) {
            fclose($out);
            flock($lockFp, LOCK_UN);
            fclose($lockFp);
            echo json_encode(['ok'=>false,'error'=>"Missing chunk $i"]); exit;
        }
        $in = fopen($chunk_file, 'rb');
        if (!$in) {
            fclose($out);
            flock($lockFp, LOCK_UN);
            fclose($lockFp);
            echo json_encode(['ok'=>false,'error'=>"Failed to read chunk $i"]); exit;
        }
        stream_copy_to_stream($in, $out);
        fclose($in);
        @unlink($chunk_file);
    }
    fclose($out);

    // verify file type and size
    if (!is_allowed_filetype($file_name, $final_path)) {
        @unlink($final_path);
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        echo json_encode(['ok'=>false,'error'=>'Invalid file type']); exit;
    }
    if (filesize($final_path) > MAX_FILE_SIZE) {
        @unlink($final_path);
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        echo json_encode(['ok'=>false,'error'=>'File too large']); exit;
    }

    $files = [['name'=>$file_name, 'tmp_name'=>$final_path]];
    [$ok,$res] = make_share($files, $sender);

    flock($lockFp, LOCK_UN);
    fclose($lockFp);
    @rmdir($chunk_dir);

    if (!$ok) echo json_encode(['ok'=>false,'error'=>$res]);
    else echo json_encode(['ok'=>true,'share'=> base_url() . '/'.basename(__FILE__).'?s='.$res]);
    exit;
}

// ------------------ CHUNKED DOWNLOAD API ------------------

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'download_chunk') {
    $share = $_GET['share'] ?? '';
    $file = $_GET['file'] ?? '';
    $chunk_index = isset($_GET['chunk_index']) ? intval($_GET['chunk_index']) : null;
    $chunk_size = isset($_GET['chunk_size']) ? intval($_GET['chunk_size']) : null;

    if (!is_valid_share_id($share) || !$file || $chunk_index === null || $chunk_size === null) {
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'Missing or invalid parameters']); exit;
    }
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Share not found']); exit; }
    $found = null;
    foreach ($meta['files'] as $f) {
        if ($f['stored'] === $file || $f['name'] === $file) { $found = $f; break; }
    }
    if (!$found) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'File not found']); exit; }

    $path = UPLOAD_DIR . "/$share/" . $found['stored'];
    if (!is_inside_dir(UPLOAD_DIR, $path) || !file_exists($path)) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'File not found']); exit; }

    $filesize = filesize($path);
    $start = $chunk_index * $chunk_size;
    $end = min($start + $chunk_size, $filesize);

    if ($start >= $filesize) {
        http_response_code(416);
        echo json_encode(['ok'=>false,'error'=>'Chunk out of range']); exit;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Length: '.($end - $start));
    header('Content-Disposition: inline; filename="'.str_replace(['"', "\n", "\r"], '', basename($found['name'])).'"');
    header('X-File-Size: '.$filesize);
    header('X-Chunk-Index: '.$chunk_index);
    header('X-Chunk-Size: '.($end - $start));
    header('X-File-Name: '.str_replace(['"', "\n", "\r"], '', basename($found['name'])));

    $fp = fopen($path, 'rb');
    fseek($fp, $start);
    $sent = 0;
    $buffer = 8192;
    while ($sent < ($end - $start) && !feof($fp)) {
        $to_read = min($buffer, ($end - $start) - $sent);
        echo fread($fp, $to_read);
        $sent += $to_read;
    }
    fclose($fp);
    exit;
}

// ------------------ UI Pages ------------------

$bg_image = get_random_bg_image();

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['s'])){
    $share = $_GET['s'];
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); }
    if (isset($_GET['file'])) serve_file($share, $_GET['file']);
    if (isset($_GET['zip'])) serve_zip($share);
    ?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Download — <?php echo htmlspecialchars($share); ?></title>
<link rel="preconnect" href="https://fonts.gstatic.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
/* Styles identical to original file (kept for UX). */
body {
    background: url('<?php echo $bg_image; ?>') center center/cover no-repeat fixed;
    font-family: 'Inter', system-ui, Segoe UI, Arial, sans-serif;
    margin: 0;
    color: #3d250f;
    min-height: 100vh;
}
.header {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 48px 0 32px 0;
}
.header img {
    height: 100px;
}
.main-layout {
    display: flex;
    flex-direction: row;
    justify-content: flex-start;
    align-items: flex-start;
    min-height: 80vh;
    margin-top: 0;
}
.container.light {
    max-width: 500px;
    background: rgba(255, 243, 230, 0.50);
    color: #3d250f;
    border-radius: 20px;
    box-shadow: 0 12px 32px rgba(218, 120, 42, 0.15);
    padding: 40px 32px 32px 32px;
    margin: 40px 0 40px 48px;
    position: relative;
    animation: fadeInUp .6s cubic-bezier(0.4, 0.4, 0, 1);
    backdrop-filter: blur(6px) brightness(1);
    text-align: left;
}
.container.light * {
    color: #3d250f;
    text-shadow: 1px 2px 12px rgba(218,120,42,0.22), 0 1px 3px #fff;
}
.h1 {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 10px;
    letter-spacing: -0.5px;
}
.small {
    color: #b88c4a;
    font-size: 0.95rem;
}
.files {
    margin-top: 30px;
}
.file {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: rgba(255,245,230,0.7);
    border-radius: 10px;
    margin-bottom: 14px;
    padding: 14px 18px;
    box-shadow: 0 2px 8px rgba(218, 120, 42, 0.09);
    transition: background 0.2s;
}
.file:hover {
    background: #ffe8cd;
}
.file-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
}
.file-name {
    font-weight: 600;
    font-size: 1.08rem;
    margin-bottom: 1px;
    color: inherit;
    text-overflow: ellipsis;
    overflow: hidden;
    max-width: 260px;
    white-space: nowrap;
}
.file-size {
    font-size: 13px;
    color: #b88c4a;
}
.btn {
    background: #3781F7;
    color: #fff !important;
    padding: 9px 18px;
    border-radius: 8px;
    font-size: 1rem;
    text-decoration: none;
    font-weight: 600;
    border: none;
    box-shadow: 0 2px 8px rgba(218, 120, 42, 0.08);
    transition: background 0.15s;
    cursor: pointer;
}
.btn.active {
    background: #e45656 !important;
}
.btn.waiting {
    background: #3781F7 !important;
}
.btn:hover {
    background: #2466d3 !important;
}
.download-all {
    display: inline-block;
    margin-top: 18px;
    margin-bottom: 10px;
}
.progress {
    height:12px;
    background:#f5e2ce;
    border-radius:6px;
    margin-top:18px;
    overflow:hidden;
    box-shadow:0 2px 8px rgba(218, 120, 42, 0.06);
}
.progress > div{
    height:100%;
    width:0;
    background:linear-gradient(90deg,#3781F7,#3aa3ff);
    transition:width .16s cubic-bezier(.4,0,.2,1);
}
.result {
    margin-top:20px;
    padding:16px;
    background:rgba(255, 236, 217, 0.95);
    border-radius:12px;
    color:#3d250f;
    font-size:1.1rem;
    display:none;
    box-shadow: 0 2px 8px rgba(218, 120, 42, 0.06);
    text-align:left;
}
@media (max-width:900px) {
    .main-layout { flex-direction: column; align-items: center; }
    .container.light { margin:40px auto; }
}
@media (max-width:600px) {
    .container.light {
        padding: 30px 10px 20px 10px;
        margin: 20px auto 20px auto;
    }
}
@keyframes fadeInUp {
    from { opacity:0; transform:translateY(40px);}
    to { opacity:1; transform:translateY(0);}
}
</style>
</head>
<body>
<div class="header" style="position:relative;">
    <img src="/assets/logo.png" alt="SendFiles Logo">
    <a href="#" id="about-link" style="position:absolute;right:32px;top:20px;color:#3781F7;font-weight:600;font-size:1.08rem;text-decoration:underline;">About</a>
</div>

<div class="main-layout">
<div class="container light">
    <div class="h1">Your files are ready!</div>
    <div class="small">Share ID: <?php echo htmlspecialchars($meta['id']); ?> &nbsp;•&nbsp; Expires: <?php echo date('Y-m-d H:i', $meta['expires']); ?></div>
    <div>
      <a class="btn download-all waiting" href="?s=<?php echo htmlspecialchars($meta['id']); ?>&zip=1">Download all (.zip)</a>
    </div>
    <div class="files">
    <?php foreach($meta['files'] as $f): ?>
        <div class="file">
            <div class="file-info">
                <span class="file-name"><?php echo htmlspecialchars($f['name'], ENT_QUOTES|ENT_HTML5); ?></span>
                <span class="file-size"><?php echo round($f['size']/1024,1); ?> KB</span>
            </div>
            <a class="btn waiting"
               href="javascript:void(0);"
               onclick="chunkedDownload(this,'<?php echo htmlspecialchars($meta['id']); ?>','<?php echo addslashes($f['stored']); ?>','<?php echo addslashes($f['name']); ?>',<?php echo $f['size']; ?>,<?php echo CHUNK_SIZE; ?>)">
                Download
            </a>
        </div>
    <?php endforeach; ?>
    </div>
    <div class="progress" id="download-prog"><div style="width:0%"></div></div>
    <?php if ($meta['sender']): ?>
        <div style="margin-top:24px;font-size:1.06rem;color:#b88c4a;">Sent by <strong><?php echo htmlspecialchars($meta['sender'], ENT_QUOTES|ENT_HTML5); ?></strong></div>
    <?php endif; ?>
</div>
</div>
<script>
function chunkedDownload(downloadBtn, shareId, fileStoredName, fileDisplayName, fileSize, chunkSize) {
    downloadBtn.classList.remove('waiting');
    downloadBtn.classList.add('active');
    const totalChunks = Math.ceil(fileSize / chunkSize);
    let chunks = [];
    const prog = document.getElementById('download-prog').firstElementChild;
    prog.style.width = '0%';

    async function fetchChunk(idx) {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', `?action=download_chunk&share=${encodeURIComponent(shareId)}&file=${encodeURIComponent(fileStoredName)}&chunk_index=${idx}&chunk_size=${chunkSize}`);
            xhr.responseType = 'arraybuffer';
            xhr.onload = function() {
                if (xhr.status === 200) {
                    resolve(xhr.response);
                } else {
                    reject('Chunk download failed: ' + xhr.status);
                }
            };
            xhr.onerror = function() { reject('Network error'); }
            xhr.send();
        });
    }

    async function start() {
        for (let i = 0; i < totalChunks; i++) {
            try {
                prog.style.width = ((i/totalChunks)*100) + '%';
                const chunk = await fetchChunk(i);
                chunks.push(chunk);
            } catch (err) {
                prog.style.width = '0%';
                downloadBtn.classList.remove('active');
                downloadBtn.classList.add('waiting');
                alert('Download error: ' + err);
                return;
            }
        }
        prog.style.width = '100%';
        const blob = new Blob(chunks, {type: 'application/octet-stream'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileDisplayName;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            prog.style.width = '0%';
            downloadBtn.classList.remove('active');
            downloadBtn.classList.add('waiting');
        }, 1500);
    }
    start();
}
</script>

<div id="about-overlay" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.25);z-index:10001;justify-content:center;align-items:center;">
    <div class="container light" style="max-width: 420px; box-shadow: 0 12px 32px rgba(218,120,42,0.22); padding:32px 28px; margin:0;">
        <div style="font-size:1.5rem;font-weight:700;margin-bottom:10px;">About SendFiles</div>
        <div style="font-size:1.08rem;line-height:1.6;">
            <p><strong>SendFiles</strong> is a secure, anonymous file sharing service built for privacy — not profit.<br>
            We’re a small, independent project with no investors, no tracking, and no interest in your data. Unlike big tech platforms, we don’t scan, analyze, or monetize your uploads.
            <p>Upload large .zip or .rar files (up to 2 GB), share a private link, and your recipient can download reliably in chunks. Files automatically expire after 2 days and are then permanently deleted.
            <p>No accounts. No logs. No ads.<br>
            Just simple, private file sharing — the way it should be.</p>
        </div>
        <button id="about-close" class="btn" style="margin-top:20px;">Close</button>
    </div>
</div>
<script>
document.getElementById('about-link').onclick = function(e){
    e.preventDefault();
    document.getElementById('about-overlay').style.display = 'flex';
};
document.getElementById('about-close').onclick = function(){
    document.getElementById('about-overlay').style.display = 'none';
};
document.getElementById('about-overlay').onclick = function(e){
    if (e.target === this) this.style.display = 'none';
};
</script>

</body>
</html>
    <?php
    exit;
}

// If no share specified, show upload UI (original UI with minor improvements for chunk ID randomness)
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SendFiles — Anonymous file sharing</title>
<link rel="preconnect" href="https://fonts.gstatic.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
/* Styles kept identical to original upload page for UX parity */
body {
    background: url('<?php echo $bg_image; ?>') center center/cover no-repeat fixed;
    font-family: 'Inter', system-ui, Segoe UI, Arial, sans-serif;
    margin: 0;
    color: #3d250f;
    min-height: 100vh;
}
.header {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 48px 0 28px 0;
}
.header img {
    height: 100px;
}
.main-layout {
    display: flex;
    flex-direction: row;
    justify-content: flex-start;
    align-items: flex-start;
    min-height: 80vh;
    margin-top: 0;
}
.wrap.light {
    max-width: 500px;
    background: rgba(255, 243, 230, 0.50);
    color: #3d250f;
    border-radius: 20px;
    box-shadow: 0 12px 32px rgba(218, 120, 42, 0.15);
    padding: 40px 32px 32px 32px;
    margin: 40px 0 40px 48px;
    position: relative;
    animation: fadeInUp .6s cubic-bezier(0.4, 0.4, 0, 1);
    backdrop-filter: blur(6px) brightness(1);
}
.wrap.light * {
    color: #3d250f;
    text-shadow: 1px 2px 12px rgba(218,120,42,0.22), 0 1px 3px #fff;
}
.hero { text-align: left; }
.title {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 10px;
    letter-spacing: -0.5px;
    color: inherit;
}
.lead {
    color: #b88c4a;
    font-size: 1.1rem;
    margin-bottom: 18px;
}
.drop {
    margin-top: 10px;
    border: 2px dashed #ffd8b5;
    border-radius: 16px;
    padding: 35px 18px;
    background: rgba(255,245,230,0.7);
    color: #b88c4a;
    font-size: 1.1rem;
    cursor: pointer;
    transition: background 0.2s;
}
.drop.dragover {
    background: #ffe8cd;
    border-color: #3781F7;
    color: #3d250f;
}
.input {
    display: flex;
    gap: 10px;
    margin-top: 22px;
}
.input input[type=text] {
    flex:1;
    padding:11px;
    border-radius:8px;
    border:1.5px solid #e3eaf7;
    font-size:1rem;
    background: #fff !important;
    color: #3d250f !important;
    transition: border 0.15s;
}
.input input[type=text]:focus {
    border:1.5px solid #3781F7;
    outline: none;
}
.input button {
    padding: 11px 22px;
    border-radius: 8px;
    background: #3781F7;
    color: #fff;
    border:none;
    font-weight:600;
    font-size:1rem;
    cursor:pointer;
    transition: background 0.15s;
    box-shadow: 0 2px 8px rgba(218, 120, 42, 0.08);
}
.input button.active {
    background: #e45656 !important;
}
.input button.waiting {
    background: #3781F7 !important;
}
.input button:hover {
    background:#2466d3 !important;
}
.progress {
    height:12px;
    background:#f5e2ce;
    border-radius:6px;
    margin-top:18px;
    overflow:hidden;
    box-shadow:0 2px 8px rgba(218, 120, 42, 0.06);
}
.progress > div{
    height:100%;
    width:0;
    background:linear-gradient(90deg,#3781F7,#3aa3ff);
    transition:width .16s cubic-bezier(.4,0,.2,1);
}
.result {
    margin-top:20px;
    padding:16px;
    background:rgba(255, 236, 217, 0.95);
    border-radius:12px;
    color:#3d250f;
    font-size:1.1rem;
    display:none;
    box-shadow: 0 2px 8px rgba(218, 120, 42, 0.06);
    text-align:left;
}
.small {
    font-size:15px;
    color:#b88c4a;
    margin-top:18px;
    text-align:left;
}
@media (max-width:900px) {
    .main-layout { flex-direction: column; align-items: center; }
    .wrap.light { margin:40px auto; }
}
@media (max-width:600px) {
    .wrap.light {
        padding: 30px 10px 20px 10px;
        margin: 20px auto 20px auto;
    }
}
@keyframes fadeInUp {
    from { opacity:0; transform:translateY(40px);}
    to { opacity:1; transform:translateY(0);}
}
</style>
</head>
<body>
<div class="header" style="position:relative;">
    <img src="/assets/logo.png" alt="SendFiles Logo">
    <a href="#" id="about-link" style="position:absolute;right:32px;top:20px;color:#3781F7;font-weight:600;font-size:1.08rem;text-decoration:underline;">About</a>
</div>
<div class="main-layout">
  <div class="wrap light">
    <div class="hero">
      <div class="title">Send files — No login needed</div>
      <div class="lead">Drag &amp; drop .zip or .rar files below or click. Files are hosted temporarily &amp; you'll get a shareable link.</div>
      <div id="drop" class="drop">
        <div id="drop-inner">
          <span style="font-size:1.3rem;">Drop files here or click to choose</span>
          <br>
          <span style="font-size:.95rem; color:#b88c4a">
            Only .zip and .rar files allowed. Up to <?php echo round(MAX_FILE_SIZE/(1024*1024*1024),2); ?> GB per file
          </span>
        </div>
        <input id="fileinput" type="file" multiple accept=".zip,.rar" style="display:none">
      </div>
      <div class="input">
        <input id="sender" type="text" placeholder="Your name (optional)">
        <button id="send" class="waiting">Upload &amp; get link</button>
      </div>
      <div class="progress" id="prog"><div style="width:0%"></div></div>
      <div class="result" id="result"></div>
      <div class="small"><svg style="vertical-align:middle;" width="16" height="16" fill="#b88c4a" viewBox="0 0 16 16"><path d="M8 1a1 1 0 0 1 1 1v1.07A6.002 6.002 0 0 1 14 9a1 1 0 1 1-2 0 4 4 0 1 0-8 0A1 1 0 0 1 1 9 6.002 6.002 0 0 1 7 3.07V2a1 1 0 0 1 1-1z"/></svg>
          Files auto-expire after <?php echo SHARE_TTL_DAYS; ?> days.
      </div>
    </div>
  </div>
</div>
<script>
const drop = document.getElementById('drop');
const fileinput = document.getElementById('fileinput');
const send = document.getElementById('send');
const prog = document.getElementById('prog').firstElementChild;
const result = document.getElementById('result');
let files = [];

drop.addEventListener('click', ()=> fileinput.click());
fileinput.addEventListener('change', e=>{
    files = Array.from(e.target.files);
    drop.classList.remove('dragover');
    drop.querySelector('#drop-inner').innerHTML = files.length ? files.length + ' file(s) selected' : 'Drop files here or click to choose';
});

['dragenter','dragover'].forEach(ev=> drop.addEventListener(ev, e=>{
    e.preventDefault();
    drop.classList.add('dragover');
}));
['dragleave','drop'].forEach(ev=> drop.addEventListener(ev, e=>{
    e.preventDefault();
    drop.classList.remove('dragover');
}));

drop.addEventListener('drop', e=>{
    e.preventDefault();
    files = Array.from(e.dataTransfer.files);
    drop.classList.remove('dragover');
    drop.querySelector('#drop-inner').innerHTML = files.length ? files.length + ' file(s) selected' : 'Drop files here or click to choose';
});

// Use crypto API for better randomness for file IDs
function randomFileId() {
    if (window.crypto && crypto.getRandomValues) {
        const arr = new Uint32Array(4);
        crypto.getRandomValues(arr);
        return Array.from(arr).map(n => n.toString(36)).join('') + Date.now().toString(36);
    }
    return Math.random().toString(36).slice(2) + (Date.now()).toString(36);
}

function uploadChunks(file, sender, onProgress, onComplete, onError) {
    const chunkSize = <?php echo CHUNK_SIZE; ?>;
    const totalChunks = Math.ceil(file.size / chunkSize);
    const fileId = randomFileId();
    let currentChunk = 0;

    function sendChunk(idx) {
        const start = idx * chunkSize;
        const end = Math.min(file.size, start + chunkSize);
        const chunkBlob = file.slice(start, end);

        const form = new FormData();
        form.append('file_id', fileId);
        form.append('chunk_index', idx);
        form.append('total_chunks', totalChunks);
        form.append('file_name', file.name);
        form.append('sender', sender);
        form.append('chunk', chunkBlob, 'chunk');

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '?action=upload_chunk');
        xhr.onload = function(){
            try {
                const r = JSON.parse(xhr.responseText);
                if (r.ok) {
                    currentChunk++;
                    if (onProgress) onProgress(currentChunk, totalChunks);
                    if (currentChunk < totalChunks) {
                        sendChunk(currentChunk);
                    } else {
                        finalize();
                    }
                } else {
                    if (onError) onError(r.error || "Chunk error");
                }
            } catch(e) {
                if (onError) onError("Chunk upload failed");
            }
        };
        xhr.onerror = ()=> { if (onError) onError("Network error"); }
        xhr.send(form);
    }

    function finalize() {
        const form = new FormData();
        form.append('file_id', fileId);
        form.append('total_chunks', totalChunks);
        form.append('file_name', file.name);
        form.append('sender', sender);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '?action=finalize');
        xhr.onload = function() {
            try {
                const r = JSON.parse(xhr.responseText);
                if (r.ok) {
                    if (onComplete) onComplete(r.share);
                } else {
                    if (onError) onError(r.error || "Finalize error");
                }
            } catch(e) {
                if (onError) onError("Finalize failed");
            }
        };
        xhr.onerror = ()=> { if (onError) onError("Network error"); }
        xhr.send(form);
    }

    sendChunk(currentChunk);
}

send.addEventListener('click', ()=>{
  if (!files.length){ alert('Choose files first'); return; }
  let allowed = files.filter(f=>{
    let ext = f.name.split('.').pop().toLowerCase();
    return ext === 'zip' || ext === 'rar';
  });
  if (allowed.length !== files.length) {
    alert('Only .zip and .rar files allowed.');
    files = [];
    fileinput.value = "";
    drop.querySelector('#drop-inner').innerHTML = `<span style="font-size:1.3rem;">Drop files here or click to choose</span><br><span style="font-size:.95rem; color:#b88c4a">Only .zip and .rar files allowed.</span>`;
    return;
  }
  send.classList.remove('waiting');
  send.classList.add('active');
  const file = allowed[0];
  const sender = document.getElementById('sender').value;
  prog.style.width = '0%';
  result.style.display = 'none';

  send.textContent = 'Uploading...';

  uploadChunks(file, sender,
    (chunk, total) => { prog.style.width = (chunk / total * 100) + '%'; },
    (shareUrl) => {
      send.textContent = 'Upload & get link';
      send.classList.remove('active');
      send.classList.add('waiting');
      result.style.display='block';
      result.innerHTML = `
        <strong>Share URL:</strong><br>
        <a id="share-link" href="${shareUrl}" target="_blank" style="color:#3781F7;font-size:1.15rem;font-weight:600;text-decoration:underline;">${shareUrl}</a>
        <br>
        <button id="copy-link-btn" style="margin:8px 0;padding:8px 16px;border-radius:8px;border:none;background:#3781F7;color:#fff;font-weight:600;cursor:pointer;">Copy Link</button>
        <span id="copy-confirm" style="margin-left:8px;color:#3781F7;display:none;">Copied!</span>
        <br><span style="font-size:.97rem; color:#b88c4a;">Copy and send this link to your recipient.</span>`;
      const copyBtn = document.getElementById('copy-link-btn');
      const shareLink = document.getElementById('share-link');
      const copyConfirm = document.getElementById('copy-confirm');
      copyBtn.onclick = function() {
          navigator.clipboard.writeText(shareLink.href)
              .then(() => {
                  copyConfirm.style.display = 'inline';
                  setTimeout(()=>{copyConfirm.style.display='none';}, 2000);
              });
      };
    },
    (err) => {
      send.textContent = 'Upload & get link';
      send.classList.remove('active');
      send.classList.add('waiting');
      alert('Error: '+err);
      prog.style.width = '0%';
    }
  );
});
</script>

<div id="about-overlay" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.25);z-index:10001;justify-content:center;align-items:center;">
    <div class="wrap light" style="max-width: 420px; box-shadow: 0 12px 32px rgba(218,120,42,0.22); padding:32px 28px; margin:0;">
        <div style="font-size:1.5rem;font-weight:700;margin-bottom:10px;">About SendFiles</div>
        <div style="font-size:1.08rem;line-height:1.6;">
            <p><strong>SendFiles</strong> is a secure, anonymous file sharing service built for privacy — not profit.<br>
            We’re a small, independent project with no investors, no tracking, and no interest in your data. Unlike big tech platforms, we don’t scan, analyze, or monetize your uploads.
            <p>Upload large .zip or .rar files (up to 2 GB), share a private link, and your recipient can download reliably in chunks. Files automatically expire after 2 days and are then permanently deleted.
            <p>No accounts. No logs. No ads.<br>
            Just simple, private file sharing — the way it should be.</p>
        </div>
        <button id="about-close" class="btn" style="margin-top:20px;">Close</button>
    </div>
</div>
<script>
document.getElementById('about-link').onclick = function(e){
    e.preventDefault();
    document.getElementById('about-overlay').style.display = 'flex';
};
document.getElementById('about-close').onclick = function(){
    document.getElementById('about-overlay').style.display = 'none';
};
document.getElementById('about-overlay').onclick = function(e){
    if (e.target === this) this.style.display = 'none';
};
</script>

</body>
</html>

<?php
// EOF
