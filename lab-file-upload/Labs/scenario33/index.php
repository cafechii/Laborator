<?php
// File Upload · Scenario 33 — SVG SSRF via xlink
$pageTitle = 'SSRF via SVG File Upload (XLink)';
$scenarioNumber = 33;
$nextScenario = sprintf('../scenario%02d/', 34);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'SVG <image> tag can reference external URL via xlink:href. If server processes SVG (e.g., converts to PNG via ImageMagick), it may fetch internal URL (SSRF).',
    'Payload: <image xlink:href="http://127.0.0.1:8080/" /> or http://169.254.169.254/',
    'Standard: SVG SSRF / XLink SSRF.',
];
$labHint = [
    'Create file ssrf.svg with: SVG with xlink:href to http://127.0.0.1:8080/scenario15/?internal=1',
    'Upload via Burp Proxy POST /scenario33/.',
    'Server may process SVG and fetch xlink:href URL (SSRF). Lab simulates by checking for xlink:href containing http://',
    'If SSRF payload present, Congratulations. Try also http://169.254.169.254/latest/meta-data/ for cloud metadata.',
    'PortSwigger: \'SSRF via SVG\'.',
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error'];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        if ($ext !== 'svg') {
            $flash = ['kind'=>'fail','title'=>'Rejected','body'=>'Only SVG allowed.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Failed','body'=>'Could not save'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $fc = file_get_contents($uploadsDir.'/'.$safeName);
            if ((stripos($fc, 'xlink:href') !== false && stripos($fc, 'http://') !== false) || stripos($fc, 'http://127.0.0.1') !== false || stripos($fc, '169.254.169.254') !== false) {
                $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 33.','body'=>'SVG SSRF payload detected: xlink:href with internal URL.'];
            } else {
                $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'SVG saved but no SSRF payload. Use <image xlink:href="http://127.0.0.1/" />'];
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 33 · UPLOAD</span><h1>SVG SSRF (XLink)</h1><p>SVG image tag triggers SSRF. Upload SVG with external URL via Burp.</p>
<div class="panel upload-form"><h2>Upload SVG</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
