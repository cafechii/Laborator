<?php
// File Upload · Scenario 01 — unrestricted file upload (no filters)
//
// Intended flaw: the upload endpoint performs NO validation, so any file
// type is accepted and an attacker can land a .php webshell that executes
// at /uploads/<name>. Path traversal is neutralized with basename() so this
// stays a clean ONE-bug lab (no extra traversal hole).

$pageTitle = 'Unrestricted File Upload';
$scenarioNumber = 1;
$nextScenario = sprintf('../scenario%02d/', 2);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Read by ../menu/navbar.php to fill the hint drawer.
// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'This lab has no file type validation. The application accepts any file and stores it in a publicly accessible directory.',
    'This is a classic OWASP Unrestricted File Upload vulnerability (CWE-434).',
    'Goal: Upload a PHP web shell and achieve remote code execution.',
];

$labHint = [
    'Open Burp Suite and configure your browser to proxy through Burp (127.0.0.1:8080).',
    'Create a file named shell.php with content: <?php echo file_get_contents(\'/etc/hostname\'); ?>',
    'In the lab, click Choose File and select shell.php, then click Upload.',
    'If Intercept is on in Burp Proxy, you will see the request - forward it.',
    'After upload, the page shows \'See the file\' link. Click it to execute the shell.',
    'This is the baseline for all file upload labs.',
];

// Endings a PHP-enabled server will run: this is what counts as "solved".
$executableExt = ['php', 'phtml', 'php5', 'php7', 'php4', 'pht', 'phar'];

$message = null;
$link    = null;
$flash   = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $message = 'Upload failed (error code ' . (int) $file['error'] . ').';
        $flash   = [
            'kind'  => 'fail',
            'title' => 'Upload failed',
            'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').',
        ];
    } else {
        $safeName = basename($file['name']); // blocks traversal, keeps the single intended bug
        $dest     = $uploadsDir . '/' . $safeName;
        if (move_uploaded_file($file['tmp_name'], $dest)) {
            $link = 'uploads/' . rawurlencode($safeName);
            $ext  = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

            if (in_array($ext, $executableExt, true)) {
                $flash = [
                    'kind'  => 'ok',
                    'title' => 'Congratulations! You solved Scenario 01.',
                    'body'  => 'The server accepted and executed ' . $safeName . '.',
                ];
            } else {
                $flash = [
                    'kind'  => 'fail',
                    'title' => 'Not solved yet',
                    'body'  => 'The file was saved, but it is not executable. Upload a PHP test file.',
                ];
            }
        } else {
            $message = 'Could not store the file (check uploads/ permissions).';
            $flash   = [
                'kind'  => 'fail',
                'title' => 'Upload failed',
                'body'  => 'The server could not save the file.',
            ];
        }
    }
}

// Keep the verdict meaningful to Burp as well as to the page.
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
        <span class="num">File Upload · SCENARIO 01 · UPLOAD</span>
        <h1>Unrestricted File Upload</h1>
        <p>No validation at all — upload a PHP web shell and execute it. The most basic file upload RCE.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
        </div>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">
                    Next scenario &rarr;
                </a>
            </div>
        <?php endif; ?>

        <?php if ($message !== null): ?>
            <p class="notice error"><?= htmlspecialchars($message, ENT_QUOTES) ?></p>
        <?php endif; ?>
        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>">See the image!</a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
