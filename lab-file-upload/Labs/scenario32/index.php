<?php
// File Upload · Scenario 32 — SSI Injection via .shtml
$pageTitle = 'Server-Side Includes Injection via .shtml Upload';
$scenarioNumber = 32;
$nextScenario = sprintf('../scenario%02d/', 33);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'SHTML files support Server-Side Includes: <!--#exec cmd="id" --> or <!--#include virtual="/etc/passwd" -->',
    'If server enables SSI for .shtml, uploading malicious SHTML leads to RCE or LFI.',
    'Standard: SSI Injection / .shtml RCE.',
];
$labHint = [
    'Create file shell.shtml with payload: <!--#exec cmd="id" --> or <!--#exec cmd="cat /etc/passwd" --> or <!--#include virtual="/etc/passwd" -->',
    'Upload via form. Use Burp Proxy to intercept POST /scenario32/.',
    'Filename must be .shtml (allowed in this lab). Content is SSI directive.',
    'After upload, click link to shell.shtml. Server will parse SSI and execute command.',
    'Check response for command output (id, /etc/passwd).',
    'PortSwigger: \'SSI injection via file upload\'.',
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error'];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        if (!in_array($ext, ['shtml','shtm','stm'], true)) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Only .shtml allowed. Try SSI payload.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Failed','body'=>'Could not save'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $fc = file_get_contents($uploadsDir.'/'.$safeName);
            if (stripos($fc, '<!--#exec') !== false || stripos($fc, '<!--#include') !== false) {
                $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 32.','body'=>'SSI directive found in '.$safeName];
            } else {
                $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'No SSI directive. Use <!--#exec cmd="id" -->'];
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 32 · UPLOAD</span><h1>SSI Injection (.shtml)</h1><p>SHTML supports SSI exec. Upload malicious .shtml via Burp.</p>
<div class="panel upload-form"><h2>Upload .shtml</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
