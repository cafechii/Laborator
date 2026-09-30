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
    'This lab runs on Windows NTFS. NTFS has Alternate Data Stream feature.',
    'Filename like shell.php::$DATA is ADS syntax.',
    'Validation sees full name with ::$DATA (not .php) but Windows saves as shell.php.',
    'This is Windows Only.',
    'Goal: Upload shell.php::$DATA',
];

$labHint = [
    'This lab works only on Windows NTFS with ADS support.',
    'Open Burp Suite, Proxy > Intercept ON, try upload shell.php - it will be blocked.',
    'Send POST /scenario17/ to Repeater (Ctrl+R).',
    'Change filename to shell.php::$DATA (exactly with ::$DATA).',
    'Content: <?php echo \'pwned\'; system($_GET[\'cmd\']); ?>',
    'Click Send. Server sees extension ::$DATA (not .php) but Windows strips ADS and saves as shell.php.',
    'Click link uploads/shell.php to execute.',
    'Standard: Windows ADS Bypass / NTFS ::$DATA.',
];

$labRootCause = [
    'cwe' => 'CWE-434: Windows ADS Bypass',
    'owasp' => 'OWASP: NTFS ADS',
    'bad' => [
        'explanation' => [
        '<strong>Programmer blocked .php extension but forgot Windows NTFS Alternate Data Stream (ADS) feature.</strong> On NTFS, filename like shell.php::$DATA is ADS syntax. Validation sees ::$DATA (not .php) but Windows saves as shell.php.',
        '<strong>Mistake:</strong> Checked extension with pathinfo() which sees ::$DATA as extension, not .php, so allows it. But Windows NTFS strips ::$DATA and saves as shell.php.',
        '<strong>Why it happens:</strong> Developer tested on Linux (ext4 has no ADS) and did not know Windows NTFS feature. This is Windows Only.',
        ],
        'code' => [
        '// VULNERABLE - Forgets Windows ADS!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // shell.php::$DATA',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION)); // Sees $DATA, not php!',
        'if ($ext == \'php\') { die(\'PHP blocked\'); }',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        '// On Windows NTFS: shell.php::$DATA is saved as shell.php! ADS stripped!',
        '?>',
        '// Attacker: filename = shell.php::$DATA - pathinfo gives $DATA - allowed, but Windows saves as shell.php - RCE!',
        ],
        'impact' => 'Attacker uses NTFS ADS ::$DATA to bypass extension check on Windows. File saved as shell.php and gets RCE. Windows Only, Linux ext4 has no ADS.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block filenames containing ::$DATA, colon :, and other ADS syntax. Reject if filename contains colon or ADS pattern. Normalize filename and check again.',
        '<strong>Rule:</strong> Block Windows special filenames and ADS.',
        ],
        'code' => [
        '// SECURE - Block ADS',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'if (strpos($filename, \'::$DATA\') !== false || strpos($filename, \':\') !== false) {',
        '  die(\'ADS not allowed\');',
        '}',
        'if (preg_match(\'/[:<>|?*]/\', $filename)) { die(\'Invalid characters\'); }',
        '$filename = basename($filename);',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Block filenames containing ::$DATA, :$DATA, :',
        'Block colon : and other Windows special chars < > | ? *',
        'Use basename() to get filename only',
        'Convert to lowercase and whitelist check',
        'Randomize filename - don\'t use user input',
        'Disable ADS on server if possible, or use Linux server',
        'Check for ADS pattern with regex',
        ],
    ],
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
        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Windows Only</strong>
        </div>

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
