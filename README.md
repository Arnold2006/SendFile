SendFile is a simple, self-hosted file sharing platform.  
It allows users to upload and share large files securely via a clean, minimal interface.  
Think of it as your personal file transfer service — fast, private, and without the clutter.  

---

## ✨ Features

- 🚀 Upload and share files with a simple drag-and-drop interface  
- 📦 Automatic file compression for efficient transfers  
- 🔒 Secure downloads with unique links  
- ⏱️ Temporary storage with automatic file expiration  
- 📱 Responsive design (works on desktop and mobile)  
- 🖼️ Rotating background images for a modern look  

---

## 🛠️ Tech Stack

- **Backend**: PHP (file handling, link generation, expiration logic)  
- **Frontend**: HTML, CSS, JavaScript (drag & drop, progress bar, UI)  
- **Storage**: Local filesystem (can be extended to S3 or other storage)  
- **Server**: Apache / Nginx + PHP-FPM  

---

## 📥 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Arnold2006/sendfile.git
   cd sendfile
Move the project files to your web server’s root directory:

bash
Copy code
cp -r sendfile /var/www/html/
Make sure the uploads/ folder is writable:

bash
Copy code
chmod -R 775 uploads
Configure PHP settings for large file uploads (in php.ini):

ini
Copy code
upload_max_filesize = 2G
post_max_size = 2G
max_execution_time = 300
Restart your web server:

bash
Copy code
sudo systemctl restart apache2
# or
sudo systemctl restart nginx
🚀 Usage
Visit your site in a browser (http://yourserver/sendfile)
Drag & drop a file or click Upload
Share the generated download link with others

⚙️ Configuration
File size limit → set in your php.ini
File expiration time → edit index.php
Storage path → configure inindex.php

📸 Screenshots
![2025-10-02 11_29_39-DesktopNotification](https://github.com/user-attachments/assets/7d43228a-3d13-458a-945e-bd631d904142)


🛡️ Disclaimer
SendFile is a hobby project for personal and team use.
Do not use it in production without adding proper security (authentication, encryption, virus scanning).

📄 License
MIT License © 2025 Ole Rasmussen
