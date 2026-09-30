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
    'This lab has no file type check. You can upload any file.',
    'The upload folder is public and you can run PHP files there.',
    'Goal: Upload a PHP shell and execute it.',
];

$labHint = [
    'Set your browser to use Burp Suite proxy (127.0.0.1:8080).',
    'Create a file named shell.php with this code: <?php echo file_get_contents(\'/etc/hostname\'); ?>',
    'In the lab, click Choose File, select shell.php, and click Upload.',
    'If Burp Intercept is on, you will see the request. Click Forward.',
    'After upload, you will see a link \'See the file\'. Click it to run your shell.',
    'This is the basic file upload attack.',
];

$labRootCause = [
    'cwe' => 'CWE-434: Unrestricted File Upload',
    'owasp' => 'OWASP: Unrestricted Upload',
    'bad' => [
        'explanation' => [
        '<strong>Programmer did not check file type at all.</strong> He thought users will only upload images, but attacker can upload any file.',
        '<strong>Mistake:</strong> No validation on server. He used user filename directly and saved in public folder where PHP can run.',
        '<strong>Why it happens:</strong> Developer forgot that client can be bypassed. Server must always validate.',
        ],
        'code' => [
        '// VULNERABLE CODE - No check at all!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // User controls this!',
        '$tmp = $_FILES[\'file\'][\'tmp_name\'];',
        'move_uploaded_file($tmp, \'uploads/\' . $filename); // Saves any file - DANGER!',
        'echo \'File uploaded: \' . $filename;',
        '?>',
        '// Attacker uploads shell.php with <?php system($_GET[\'cmd\']); ?>',
        '// Then visits /uploads/shell.php?cmd=id and gets RCE',
        ],
        'impact' => 'Attacker uploads PHP shell and gets Remote Code Execution (RCE). Full control of server, read database, steal files.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Always validate on server side. Use whitelist, not blacklist. Check extension, MIME type, and content.',
        '<strong>Rule:</strong> Never trust client. Randomize filename and store outside web root.',
        ],
        'code' => [
        '// SECURE CODE',
        '<?php',
        '$allowedExt = [\'png\',\'jpg\',\'jpeg\',\'gif\'];',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, $allowedExt)) { die(\'Invalid extension\'); }',
        '',
        '$finfo = finfo_open(FILEINFO_MIME_TYPE);',
        '$mime = finfo_file($finfo, $_FILES[\'file\'][\'tmp_name\']);',
        'if (!in_array($mime, [\'image/png\',\'image/jpeg\',\'image/gif\'])) { die(\'Invalid MIME\'); }',
        '',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext; // Random name',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'/var/uploads/\' . $newName);',
        'chmod(\'/var/uploads/\' . $newName, 0644);',
        '?>',
        '// .htaccess in uploads/: php_flag engine off',
        ],
        'steps' => [
        'Whitelist allowed extensions (png, jpg) - not blacklist',
        'Check MIME with finfo_file() not $_FILES[\'type\']',
        'Verify image with getimagesize()',
        'Generate random filename - don\'t use user input',
        'Store outside web root /var/uploads/',
        'Disable PHP execution in uploads with .htaccess',
        'Set file permissions 0644',
        ],
    ],
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
