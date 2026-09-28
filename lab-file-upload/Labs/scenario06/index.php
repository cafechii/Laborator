<?php
// File Upload · Scenario 06 — Overwrite Existing File
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'File Overwrite via Insecure Upload (Avatar Overwrite)';
$scenarioNumber = 6;
$nextScenario = sprintf('../scenario%02d/', 7);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'The application allows overwriting existing files by using predictable filenames without collision protection.',
    'If avatar.jpg already exists, uploading a new file with same name overwrites it.',
    'OWASP: Insecure File Upload - Overwrite. Goal: Overwrite avatar.jpg',
];

$labHint = [
    'Observe the page: it says avatar.jpg already exists in uploads/.',
    'Create a file named exactly avatar.jpg (case-sensitive).',
    'Content can be PHP or just text: overwrite test.',
    'Upload via form - no Burp needed, but you can intercept to see POST.',
    'After upload, click \'Open the uploaded file\' - you replaced the original avatar.',
    'In real apps, overwriting config or other users avatars leads to RCE or defacement.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$fixture = $uploadsDir . '/avatar.jpg';
if (!is_file($fixture)) {
    file_put_contents($fixture, "ORIGINAL_AVATAR\n");
}

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server rejected the upload.'];
    } else {
        $safeName = basename($file['name']);
        $dest = $uploadsDir . '/' . $safeName;
        $before = is_file($dest) ? hash_file('sha256', $dest) : null;
        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the file.'];
        } else {
            $after = hash_file('sha256', $dest);
            if ($safeName === 'avatar.jpg') {
                $link = 'uploads/avatar.jpg';
                $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 06.', 'body' => 'The existing avatar.jpg was overwritten without collision protection.'];
            } else {
                http_response_code(202);
                $flash = ['kind' => 'info', 'title' => 'File stored', 'body' => 'Use the existing filename avatar.jpg to test overwrite behavior.'];
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
        <span class="num">File Upload · SCENARIO 06 · UPLOAD</span>
        <h1>File Overwrite (Insecure Naming)</h1>
        <p>Uploads overwrite existing files. Replace avatar.jpg with your file.</p>

        <div class="panel upload-form">
            <h2>Replace the avatar</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
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
