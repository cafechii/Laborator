<?php
// File Upload · Scenario 26 — Image Processor Command Injection
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'RCE via ImageMagick Command Injection (ImageTragick)';
$scenarioNumber = 26;
$nextScenario = sprintf('../scenario%02d/', 27);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'ImageMagick processes image and uses filename in shell command without escaping. Inject | or ; or backtick.',
    'Payload: filename contains id or |echo pwned',
    'Standard: ImageTragick / ImageMagick RCE (CVE-2016-3714, CVE-2020-29599).',
];

$labHint = [
    'In Burp Suite, intercept image upload POST /scenario26/.',
    'Send to Repeater. Change filename to: ";id;" or "|id" or backtick id backtick',
    'Content: valid image but filename is injection point.',
    'Example: filename="|echo id > /tmp/pwned" or use ImageMagick payload: \'"|id;"\'',
    'Server runs identify / convert with filename in shell - injection executes.',
    'Check response for command output. PortSwigger: \'RCE via image upload\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    if ($file['error'] !== UPLOAD_ERR_OK || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the image.'];
    } else {
        $command = 'identify ' . ($uploadsDir . '/' . $safeName) . ' 2>&1';
        $output = (string) @shell_exec($command);
        $extraOutput = $output;
        if (strpos($output, 'IMAGE_PROCESSOR_OK') !== false || is_file('/tmp/scenario26-proof') || preg_match('/uid=\d+/i', $output)) {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 26.', 'body' => 'The image processor command was injected through the filename.'];
        } else {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'No command injection', 'body' => 'The image was processed, but the command was not injected. Intercept the upload in Burp and append ;echo IMAGE_PROCESSOR_OK to the filename.'];
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
        <span class="num">File Upload · SCENARIO 26 · UPLOAD</span>
        <h1>ImageMagick Command Injection</h1>
        <p>ImageMagick uses filename in shell command. Inject via filename using Burp Repeater.</p>

        <div class="panel upload-form">
            <h2>Process an image</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select an image:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit">Process image</button>
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
