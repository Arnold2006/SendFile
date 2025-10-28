<?php
// Secure file sharing app with chunked upload & download.
// Warm, semi-transparent card style for forms only (.light style with text shadow for readability).
const BASE_URL = ''; 
const UPLOAD_DIR = __DIR__ . '/uploads';
const DATA_DIR = __DIR__ . '/data';
const TMP_DIR = __DIR__ . '/tmp_chunks';
const SHARE_ID_LEN = 16;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 2 GB per file
const CHUNK_SIZE = 20 * 1024 * 1024; // 20MB per chunk
const SHARE_TTL_DAYS = 2;

function get_random_bg_image() {
    $sources = [
        "https://picsum.photos/1920/1080"
    ];
    return $sources[array_rand($sources)];
}

if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0755, true);
if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0755, true);
if (!is_dir(TMP_DIR)) mkdir(TMP_DIR, 0755, true);

function base_url(){
    if (BASE_URL !== '') return rtrim(BASE_URL, '/');
    $s = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $s .= '://' . $_SERVER['HTTP_HOST'];
    $s .= rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\');
    return rtrim($s, '/');
}
function json_save($id, $data){ file_put_contents(DATA_DIR . "/$id.json", json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)); }
function json_load($id){ $f = DATA_DIR . "/$id.json"; if (!file_exists($f)) return null; return json_decode(file_get_contents($f), true); }
function gen_id($len=16){ return bin2hex(random_bytes($len/2)); }
function sanitize_filename($name){
    $name = preg_replace('/[^A-Za-z0-9_\.-]/', '', $name);
    $name = ltrim($name, '.');
    if (!$name) $name = gen_id(8) . ".file";
    return $name;
}
function is_allowed_filetype($filename, $tmp_path) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, ['zip', 'rar'])) return false;
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $tmp_path);
        finfo_close($finfo);
        $zip_mimes = ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'];
        $rar_mimes = ['application/x-rar', 'application/x-rar-compressed', 'application/octet-stream'];
        if ($ext === 'zip' && !in_array($mime, $zip_mimes)) return false;
        if ($ext === 'rar' && !in_array($mime, $rar_mimes)) return false;
    }
    return true;
}
function make_share($files, $sender_name=''){
    $id = gen_id(SHARE_ID_LEN);
    $dir = UPLOAD_DIR . "/$id";
    mkdir($dir, 0755, true);
    $meta = [
        'id'=>$id,
        'created'=>time(),
        'expires'=>time() + SHARE_TTL_DAYS*86400,
        'files'=>[],
        'sender'=> htmlspecialchars($sender_name, ENT_QUOTES|ENT_HTML5),
    ];
    foreach($files as $f){
        $ext = strtolower(pathinfo($f['name'], PATHINFO_EXTENSION));
        $randname = gen_id(16) . ($ext ? "." . $ext : "");
        $target = $dir . '/' . $randname;
        $i=1; $base=$randname; while(file_exists($target)) { $randname = gen_id(16) . ($ext ? "." . $ext : ""); $target = $dir . '/' . $randname; $i++; }
        if (!rename($f['tmp_name'], $target)) return [false, "Failed to move uploaded file"];
        $meta['files'][] = [
            'name' => htmlspecialchars($f['name'], ENT_QUOTES|ENT_HTML5),
            'stored' => $randname,
            'size' => filesize($target)
        ];
    }
    json_save($id, $meta);
    return [true, $id];
}
function serve_file($share, $file){
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); exit('Share not found'); }
    $found = null;
    foreach ($meta['files'] as $f) {
        if ($f['name'] === $file || $f['stored'] === $file) { $found = $f; break; }
    }
    if (!$found) { http_response_code(404); exit('File not found'); }
    $path = UPLOAD_DIR . "/$share/" . $found['stored'];
    if (!file_exists($path)) { http_response_code(404); exit('File not found'); }
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename=".basename($found['name'])."');
    header('Content-Length: '.filesize($path));
    readfile($path);
    exit;
}
function serve_zip($share){
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); exit('Share not found'); }
    $dir = UPLOAD_DIR . "/$share";
    $zipname = tempnam(sys_get_temp_dir(), 'zip');
    $zip = new ZipArchive();
    if ($zip->open($zipname, ZipArchive::CREATE | ZipArchive::OVERWRITE)!==TRUE) exit('Could not create zip');
    foreach($meta['files'] as $f){
        $filepath = $dir.'/'.$f['stored'];
        if (!file_exists($filepath)) {
            error_log("File missing for ZIP: $filepath");
            continue;
        }
        if (filesize($filepath) === 0) {
            error_log("File is zero bytes: $filepath");
            continue;
        }
        $zip->addFile($filepath, $f['name']);
    }
    $zip->close();
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename=". $share .'.zip"');
    header('Content-Length: '.filesize($zipname));
    readfile($zipname);
    unlink($zipname);
    exit;
}

// === CHUNKED UPLOAD API ===
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action']==='upload_chunk') {
    $file_id = $_POST['file_id'] ?? '';
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
    $chunk_dir = TMP_DIR . "/$file_id";
    if (!is_dir($chunk_dir)) mkdir($chunk_dir, 0755, true);
    $chunk_path = $chunk_dir . "/chunk_$chunk_index";
    if (!move_uploaded_file($_FILES['chunk']['tmp_name'], $chunk_path)) {
        echo json_encode(['ok'=>false,'error'=>'Failed to save chunk']); exit;
    }
    echo json_encode(['ok'=>true,'received'=>$chunk_index]);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action']==='finalize') {
    $file_id = $_POST['file_id'] ?? '';
    $total_chunks = isset($_POST['total_chunks']) ? intval($_POST['total_chunks']) : null;
    $file_name = $_POST['file_name'] ?? '';
    $sender = $_POST['sender'] ?? '';

    if (!$file_id || $total_chunks===null || !$file_name) {
        echo json_encode(['ok'=>false,'error'=>'Missing finalize parameters']); exit;
    }
    $chunk_dir = TMP_DIR . "/$file_id";
    $final_path = $chunk_dir . "/final";
    $out = fopen($final_path, 'wb');
    for ($i=0; $i<$total_chunks; $i++) {
        $chunk_file = $chunk_dir . "/chunk_$i";
        if (!file_exists($chunk_file)) {
            fclose($out);
            echo json_encode(['ok'=>false,'error'=>"Missing chunk $i"]); exit;
        }
        $in = fopen($chunk_file, 'rb');
        stream_copy_to_stream($in, $out);
        fclose($in);
        unlink($chunk_file);
    }
    fclose($out);

    if (!is_allowed_filetype($file_name, $final_path)) {
        unlink($final_path);
        echo json_encode(['ok'=>false,'error'=>'Invalid file type']); exit;
    }
    if (filesize($final_path) > MAX_FILE_SIZE) {
        unlink($final_path);
        echo json_encode(['ok'=>false,'error'=>'File too large']); exit;
    }
    $files = [['name'=>$file_name, 'tmp_name'=>$final_path]];
    [$ok,$res] = make_share($files, $sender);
    if (is_dir($chunk_dir)) rmdir($chunk_dir);
    if (!$ok) echo json_encode(['ok'=>false,'error'=>$res]);
    else echo json_encode(['ok'=>true,'share'=> base_url() . '/'.basename(__FILE__).'?s='.$res]);
    exit;
}

// === CHUNKED DOWNLOAD API ===
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'download_chunk') {
    $share = $_GET['share'] ?? '';
    $file = $_GET['file'] ?? '';
    $chunk_index = isset($_GET['chunk_index']) ? intval($_GET['chunk_index']) : null;
    $chunk_size = isset($_GET['chunk_size']) ? intval($_GET['chunk_size']) : null;

    if (!$share || !$file || $chunk_index === null || $chunk_size === null) {
        http_response_code(400);
        echo json_encode(['ok'=>false,'error'=>'Missing parameters']); exit;
    }
    $meta = json_load($share);
    if (!$meta) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Share not found']); exit; }
    $found = null;
    foreach ($meta['files'] as $f) {
        if ($f['stored'] === $file || $f['name'] === $file) { $found = $f; break; }
    }
    if (!$found) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'File not found']); exit; }
    $path = UPLOAD_DIR . "/$share/" . $found['stored'];
    if (!file_exists($path)) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'File not found']); exit; }

    $filesize = filesize($path);
    $start = $chunk_index * $chunk_size;
    $end = min($start + $chunk_size, $filesize);

    if ($start >= $filesize) {
        http_response_code(416);
        echo json_encode(['ok'=>false,'error'=>'Chunk out of range']); exit;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Length: '.($end - $start));
    header('Content-Disposition: inline; filename=".basename($found['name'])."');
    header('X-File-Size: '.$filesize);
    header('X-Chunk-Index: '.$chunk_index);
    header('X-Chunk-Size: '.($end - $start));
    header('X-File-Name: '.basename($found['name']));

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