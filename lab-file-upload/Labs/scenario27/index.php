<?php
// File Upload · Scenario 27 — uWSGI Configuration Upload
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'RCE via uWSGI Configuration File Upload';
$scenarioNumber = 27;
$nextScenario = sprintf('../scenario%02d/', 28);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'uWSGI allows exec:// scheme in config files. Uploading malicious uwsgi.ini with exec://id leads to RCE.',
    'Standard: uWSGI ini RCE / Config Injection. Goal: Upload uwsgi.ini with exec.',
];

$labHint = [
    'Create file uwsgi.ini with: [uwsgi] exec = id or exec://id or exec-asap = id',
    'Alternatively: [uwsgi] ; exec scheme socket = :0 exec = /bin/bash -c \'id > /tmp/pwned\'',
    'Upload via form. Use Burp Proxy to intercept POST /scenario27/.',
    'Server loads config with uWSGI and executes exec command.',
    'Check response for command output or file creation.',
    'PortSwigger: \'RCE via config upload\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    $contents = (string) @file_get_contents($file['tmp_name']);
    if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) !== 'ini') {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Upload rejected', 'body' => 'Upload a .ini configuration file.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the configuration.'];
    } elseif (!preg_match('/@\(?exec:\/\/([^\r\n\)]+)\)?/i', $contents, $command)) {
        http_response_code(422);
        $flash = ['kind' => 'fail', 'title' => 'No exec scheme', 'body' => 'The configuration has no @exec directive.'];
    } else {
        $extraOutput = (string) @shell_exec($command[1]);
        if (strpos($extraOutput, 'UWSGI_OK') !== false || trim($extraOutput) !== '') {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 27.', 'body' => 'The configuration parser evaluated the unsafe exec scheme.'];
        } else {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'Command produced no output', 'body' => 'The exec directive executed but produced no output. Use a harmless command like printf UWSGI_OK.'];
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
        <span class="num">File Upload · SCENARIO 27 · UPLOAD</span>
        <h1>uWSGI Config RCE</h1>
        <p>uWSGI exec:// scheme in ini leads to RCE. Upload malicious uwsgi.ini via Burp.</p>

        <div class="panel upload-form">
            <h2>Upload a uWSGI configuration</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select uwsgi.ini:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".ini,text/plain" />
                <button class="primary-button" type="submit">Load configuration</button>
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
