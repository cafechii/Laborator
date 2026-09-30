<?php
// File Upload · Scenario 14 — ZIP Decompression Bomb
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'DoS via Zip Bomb (Decompression Bomb)';
$scenarioNumber = 14;
$nextScenario = sprintf('../scenario%02d/', 15);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'Server checks compressed size but not uncompressed size. A tiny ZIP can expand to GBs (42.zip).',
    'Standard: Zip Bomb / Decompression Bomb (CWE-409). Goal: Upload small ZIP that expands >8MB.',
];

$labHint = [
    'Create a zip bomb: Use Python to create highly compressible file: python3 -c "import zipfile; z=zipfile.ZipFile(\'bomb.zip\',\'w\',zipfile.ZIP_DEFLATED); z.writestr(\'big.txt\',\'0\'*1024*1024*20); z.close()"',
    'This creates ~20KB ZIP that expands to 20MB.',
    'Upload bomb.zip via form. Use Burp to intercept and confirm upload.',
    'Server will decompress and check size - if >8MB, it detects bomb and shows Congratulations (simulated DoS).',
    'PortSwigger: \'DoS via file upload\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        $flash = ['kind' => 'fail', 'title' => 'ZIP support unavailable', 'body' => 'Use the Dockerfile for this lab.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The archive was not received.'];
    } else {
        $zip = new ZipArchive();
        if ($zip->open($file['tmp_name']) !== true) {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'Invalid archive', 'body' => 'The file is not a readable ZIP archive.'];
        } else {
            $expanded = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $expanded += (int) ($stat['size'] ?? 0);
            }
            $compressed = filesize($file['tmp_name']);
            $zip->close();
            if ($compressed < 200000 && $expanded > 8000000) {
                $extraOutput = 'compressed bytes: ' . $compressed . "\nuncompressed bytes: " . $expanded;
                $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 14.', 'body' => 'The server accepted a small archive with a dangerous expansion ratio.'];
            } else {
                http_response_code(422);
                $flash = ['kind' => 'fail', 'title' => 'Archive is not oversized enough', 'body' => 'Use a small, highly compressible archive with more than 8 MB of uncompressed data.'];
            }
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
        <span class="num">File Upload · SCENARIO 14 · UPLOAD</span>
        <h1>Zip Bomb (Decompression Bomb)</h1>
        <p>Small ZIP expands to huge size causing DoS. Upload highly compressible ZIP.</p>

        <div class="panel upload-form">
            <h2>Upload a compressed archive</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a ZIP:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".zip,application/zip" />
                <button class="primary-button" type="submit">Check archive</button>
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
