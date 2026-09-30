<?php
// File Upload · Scenario 12 — SVG Stored XSS
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'Stored XSS via SVG File Upload';
$scenarioNumber = 12;
$nextScenario = sprintf('../scenario%02d/', 13);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'SVG is XML-based and can contain JavaScript: <script>alert(1)</script> or <svg onload=alert(1)>',
    'If server serves SVG from same origin without sanitization, stored XSS occurs.',
    'Standard: SVG Stored XSS (OWASP). Goal: Upload malicious SVG.',
];

$labHint = [
    'Create file xss.svg with payload: <svg xmlns=\'http://www.w3.org/2000/svg\' onload=\'alert(document.domain)\'><text>test</text></svg>',
    'Alternatively: <?xml version=\'1.0\'?><svg><script>alert(1)</script></svg>',
    'Upload via form. Intercept with Burp Proxy to ensure Content-Type is image/svg+xml or application/octet-stream.',
    'After upload, click \'See the file\' link. The SVG will render and execute JS in same origin.',
    'Burp: Check response Content-Type is image/svg+xml - browser will execute.',
    'PortSwigger: \'Stored XSS via SVG\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) !== 'svg') {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Upload rejected', 'body' => 'Only SVG files are accepted in this lab.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the file.'];
    } else {
        $contents = (string) @file_get_contents($uploadsDir . '/' . $safeName);
        $link = 'uploads/' . rawurlencode($safeName);
        if (preg_match('/<script\b|\bon(load|error|click)\s*=/i', $contents)) {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 12.', 'body' => 'The SVG contains active browser-side content.'];
        } else {
            http_response_code(202);
            $flash = ['kind' => 'info', 'title' => 'SVG stored', 'body' => 'The file is stored, but it has no script or event handler.'];
        }
    }
}

if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) {
    http_response_code(422);
}
?>
<!DOCTYPE html>
<html lang="en">
<?php include __DIR__ . '/../menu/header.php'; ?>
<body>
<?php include __DIR__ . '/../menu/navbar.php'; ?>

    <main class="bench">
        <span class="num">File Upload · SCENARIO 12 · UPLOAD</span>
        <h1>SVG Stored XSS</h1>
        <p>SVG can contain JavaScript. Upload SVG with onload alert via Burp.</p>

        <div class="panel upload-form">
            <h2>Upload an SVG</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select an SVG:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".svg,image/svg+xml" />
                <button class="primary-button" type="submit">Upload</button>
            </form>
        </div>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($extraOutput !== null): ?>
            <pre class="panel hint-code" aria-label="Parser output"><?= htmlspecialchars($extraOutput, ENT_QUOTES) ?></pre>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">Next scenario &rarr;</a>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
