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
    'SVG is XML based and can contain JavaScript.',
    'Tags like <script>alert(1)</script> or <svg onload=alert(1)> run JS.',
    'If server shows SVG file, XSS happens.',
    'Goal: Upload SVG with XSS.',
];

$labHint = [
    'Create file xss.svg with content: <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>',
    'Or: <svg><script>alert(1)</script></svg>',
    'Upload xss.svg via form. Use Burp to intercept if needed.',
    'After upload, click link to open SVG. JavaScript will run.',
    'You should see alert popup.',
    'Standard: SVG XSS / Stored XSS via SVG.',
];

$labRootCause = [
    'cwe' => 'CWE-79: XSS via SVG',
    'owasp' => 'OWASP: SVG XSS',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed SVG uploads and displayed SVG directly.</strong> SVG is XML and can contain JavaScript like <script>alert(1)</script> or <svg onload=alert(1)>.',
        '<strong>Mistake:</strong> Thought SVG is just image, but SVG is XML with JavaScript support. No sanitization of SVG content.',
        '<strong>Why it happens:</strong> Developer did not know SVG can contain JavaScript. Allowed .svg extension without checking content.',
        ],
        'code' => [
        '// VULNERABLE - Allows SVG without sanitization!',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if ($ext == \'svg\' || $ext == \'png\' || $ext == \'jpg\') {',
        '  move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '  echo \'<img src="uploads/\' . $_FILES[\'file\'][\'name\'] . \'">\';',
        '}',
        '?>',
        '// Attacker uploads xss.svg:',
        '// <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>',
        '// When victim visits page, browser loads SVG and runs onload JavaScript! XSS!',
        ],
        'impact' => 'Attacker uploads SVG with JavaScript. When victim views SVG or page includes SVG, JavaScript runs. Stored XSS, can steal cookies, session.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Don\'t allow SVG if not needed. If needed, sanitize SVG to remove <script>, onload, onerror, and other dangerous tags/attributes. Serve SVG with Content-Disposition: attachment or with CSP.',
        '<strong>Rule:</strong> SVG is not just image, it is XML with JS. Must be sanitized.',
        ],
        'code' => [
        '// SECURE - Block SVG or sanitize',
        '<?php',
        '// Option 1: Block SVG completely - safest',
        '$allowed = [\'png\',\'jpg\',\'jpeg\',\'gif\']; // No svg!',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, $allowed)) { die(\'SVG not allowed\'); }',
        '// Option 2: If SVG needed, sanitize',
        '// Use library like enshrined/svg-sanitize',
        '// $sanitizer = new Sanitizer();',
        '// $cleanSVG = $sanitizer->sanitize(file_get_contents($tmp));',
        '?>',
        ],
        'steps' => [
        'Block SVG upload if not needed - safest',
        'If SVG needed, use sanitizer library like svg-sanitize',
        'Remove <script>, onload, onerror, onclick, and other event handlers',
        'Remove javascript: URLs',
        'Serve SVG with Content-Disposition: attachment to force download',
        'Set CSP header: Content-Security-Policy: script-src \'none\'',
        'Set X-Content-Type-Options: nosniff',
        'Validate SVG is really SVG with XML parser',
        ],
    ],
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
