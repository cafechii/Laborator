<?php
// File Upload · Scenario 17 — Windows Alternate Data Stream Name
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'Web Shell Upload via Windows Alternate Data Stream (ADS)';
$scenarioNumber = 17;
$nextScenario = sprintf('../scenario%02d/', 18);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'On NTFS, filename::$DATA is Alternate Data Stream syntax. Validation sees full name (allowed), but filesystem saves main stream as .php.',
    'Example: shell.php::$DATA is saved as shell.php on Windows.',
    'Standard: Windows ADS Bypass / ::$DATA. Goal: shell.php::$DATA',
];

$labHint = [
    'In Burp Suite, turn Intercept ON.',
    'Upload shell.php - blocked.',
    'Send POST /scenario17/ to Repeater.',
    'Change filename to shell.php::$DATA or shell.php:::$DATA or shell.php::$INDEX_ALLOCATION',
    'Content: <?php echo \'pwned\'; ?>',
    'Send. Server checks extension? It sees ::$DATA (not .php) but Windows strips ADS and saves as shell.php.',
    'Click link to execute. PortSwigger: \'Web shell upload via ADS\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $requested = basename($file['name']);
    $ext = strtolower(pathinfo($requested, PATHINFO_EXTENSION));
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server rejected the upload.'];
    } elseif ($ext === 'php') {
        http_response_code(403);
        $flash = ['kind' => 'fail', 'title' => 'Blocked by blacklist', 'body' => 'Files ending with .php are strictly blocked by the extension blacklist.'];
    } elseif (stripos($requested, '::$data') === false) {
        http_response_code(422);
        $flash = ['kind' => 'fail', 'title' => 'Not solved yet', 'body' => 'Use the Windows Alternate Data Stream suffix ::$DATA to bypass the extension filter.'];
    } else {
        $stored = preg_replace('/::\$data$/i', '', $requested);
        $dest = $uploadsDir . '/' . $stored;
        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the file.'];
        } else {
            $link = 'uploads/' . rawurlencode($stored);
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 17.', 'body' => 'Windows NTFS Alternate Data Stream syntax bypassed the blacklist and stored ' . htmlspecialchars($stored, ENT_QUOTES) . '.'];
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
        <span class="num">File Upload · SCENARIO 17 · UPLOAD</span>
        <h1>Windows ADS Bypass</h1>
        <p>NTFS ::$DATA bypasses blacklist. Use Burp Repeater to upload shell.php::$DATA.</p>

        <div class="panel upload-form">
            <h2>Upload a Windows-style filename</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a PHP file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
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
