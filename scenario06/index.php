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
    'The app lets you overwrite existing files.',
    'A file named avatar.jpg already exists in uploads/.',
    'If you upload new file with same name, it replaces old file.',
    'Goal: Overwrite avatar.jpg with your file.',
];

$labHint = [
    'Look at page - it says avatar.jpg already exists in uploads/.',
    'Create a file with exactly same name: avatar.jpg (lowercase).',
    'Put any content you want, for example \'hacked\' or PHP code.',
    'Upload it via the form. No need for Burp, but you can use it.',
    'Click \'Open the uploaded file\' - you will see old file is replaced.',
    'In real world, you can overwrite other users avatar or config file.',
];

$labRootCause = [
    'cwe' => 'CWE-434: File Overwrite',
    'owasp' => 'OWASP: Overwrite Attack',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed overwriting existing files.</strong> If file with same name exists, new upload replaces old file.',
        '<strong>Mistake:</strong> No check if file already exists. No random filename. Used user-controlled filename directly.',
        '<strong>Why it happens:</strong> Developer wanted simple code and did not think about file collision attack.',
        ],
        'code' => [
        '// VULNERABLE - Allows overwrite!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // User controls name',
        '$dest = \'uploads/\' . $filename;',
        '// No check if file exists!',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], $dest); // Overwrites existing file!',
        'echo \'Uploaded to \' . $dest;',
        '?>',
        '// Victim has avatar.jpg in uploads/',
        '// Attacker uploads new avatar.jpg with malicious content',
        '// Old avatar.jpg is replaced! Can overwrite config files, other users avatars',
        ],
        'impact' => 'Attacker overwrites existing files like avatar.jpg, config.php, or other users files. Can cause DoS, defacement, or RCE if overwrites PHP file.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Generate random filename for each upload. Never use user-controlled filename directly. Check if file exists.',
        '<strong>Rule:</strong> Randomize filename and store mapping in database.',
        ],
        'code' => [
        '// SECURE - Random filename, no overwrite',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        '$allowed = [\'png\',\'jpg\',\'jpeg\',\'gif\'];',
        'if (!in_array($ext, $allowed)) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        '$dest = \'uploads/\' . $newName;',
        'if (file_exists($dest)) {',
        '  $newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        '  $dest = \'uploads/\' . $newName;',
        '}',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], $dest);',
        '?>',
        ],
        'steps' => [
        'Generate random filename with random_bytes()',
        'Never use user-controlled filename directly',
        'Check if file exists before saving',
        'Store mapping user_id -> random filename in database',
        'Use UUID or timestamp + random for uniqueness',
        'Set proper permissions 0644',
        ],
    ],
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
