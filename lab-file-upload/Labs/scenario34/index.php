<?php
// File Upload · Scenario 34 — ffmpeg HLS SSRF / File Read
$pageTitle = 'SSRF / LFI via FFmpeg HLS Playlist Upload';
$scenarioNumber = 34;
$nextScenario = null;
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'FFmpeg processes HLS playlists (m3u8). A playlist can reference local file as segment: file:///etc/passwd or http://127.0.0.1:8080/internal',
    'If application uses ffmpeg to transcode uploaded video, HLS injection leads to LFI/SSRF.',
    'Standard: FFmpeg HLS SSRF / LFI via m3u8 (HackerOne reports, CVE). Goal: Upload malicious m3u8',
];
$labHint = [
    'Create file exploit.m3u8 with content: #EXTM3U and file:///etc/passwd segment',
    'For SSRF: Replace file:///etc/passwd with http://127.0.0.1:8080/scenario15/?internal=1',
    'In Burp Suite, upload exploit.m3u8 via POST /scenario34/. Set filename to exploit.m3u8 or exploit.mp4 (lab checks extension m3u8, mp4, avi).',
    'Server simulates ffmpeg processing HLS playlist and reading referenced file.',
    'If payload contains file:///etc/passwd or http://127.0.0.1, Congratulations with file content.',
    'This is first lab for Audio/Video branch. PortSwigger style: \'SSRF via video upload\'.',
];
$link = null; $linkLabel = 'See the file'; $flash = null; $extraOutput = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error'];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        if (!in_array($ext, ['m3u8','m3u','mp4','avi','mov','mp3'], true)) {
            $flash = ['kind'=>'fail','title'=>'Rejected','body'=>'Only media files allowed: m3u8, mp4, avi, mp3'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Failed','body'=>'Could not save'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $fc = file_get_contents($uploadsDir.'/'.$safeName);
            $isHls = stripos($fc, '#EXTM3U') !== false || stripos($fc, '#EXT-X-MEDIA') !== false || stripos($fc, 'file://') !== false || stripos($fc, 'http://') !== false;
            if ($isHls && (stripos($fc, 'file:///etc/passwd') !== false || stripos($fc, '/etc/passwd') !== false || stripos($fc, 'http://127.0.0.1') !== false || stripos($fc, '169.254.169.254') !== false)) {
                $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 34.','body'=>'ffmpeg HLS payload detected: '.$safeName.' references internal file/URL.'];
                $extraOutput = "Simulated ffmpeg output:\n[Parsed HLS]\nWould read: ".htmlspecialchars(substr($fc,0,200));
            } else {
                $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'Upload HLS playlist with file:///etc/passwd or internal URL.'];
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 34 · UPLOAD</span><h1>FFmpeg HLS SSRF / LFI</h1><p>FFmpeg HLS playlist can read file:///etc/passwd. Upload malicious m3u8 via Burp.</p>
<div class="panel upload-form"><h2>Upload Media</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($extraOutput !== null): ?><pre class="panel hint-code"><?= htmlspecialchars($extraOutput, ENT_QUOTES) ?></pre><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
