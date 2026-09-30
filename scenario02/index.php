<?php
// File Upload · Scenario 02 — client-side validation bypass
//
// Intended flaw: the ONLY check is js/checker.js, running in the browser.
// The server side accepts whatever arrives, so a request that never touched
// the script (Repeater, curl, devtools) stores any file the form rejects.
// Path traversal is neutralized with basename() to keep this a ONE-bug lab.

$pageTitle = 'Web Shell Upload via Client-Side Validation Bypass';
$scenarioNumber = 2;
$nextScenario = sprintf('../scenario%02d/', 3);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'The app checks file extension only in browser JavaScript (checker.js).',
    'The server does not check extension again.',
    'This is Client-Side Validation Bypass.',
    'Goal: Bypass the browser check with Burp Suite.',
];

// Read by ../menu/navbar.php to fill the hint drawer.
$labHint = [
    'Open Burp Suite, go to Proxy > Intercept, turn Intercept ON.',
    'Try to upload shell.php in the browser. The browser blocks it and says Only PNG allowed.',
    'Now select a valid file like image.png and click Upload.',
    'Burp will catch the POST request to /scenario02/.',
    'Look at Raw tab. Find filename="image.png" in multipart body.',
    'Change it to filename="shell.php" and change file content to <?php echo \'pwned\'; ?>',
    'Click Forward. The server will accept it because it does not check.',
    'Click the link to run the file. Standard name: Client-Side Bypass.',
];

$labRootCause = [
    'cwe' => 'CWE-602: Client-Side Enforcement',
    'owasp' => 'OWASP: Client-Side Bypass',
    'bad' => [
        'explanation' => [
        '<strong>Programmer checked file type only in browser JavaScript (checker.js).</strong> He thought browser check is enough.',
        '<strong>Mistake:</strong> JavaScript can be bypassed with Burp Suite, curl, or disabling JS. Server had no check at all.',
        '<strong>Why it happens:</strong> Developer trusted client. Client-side validation is only for user experience, not security.',
        ],
        'code' => [
        '// checker.js - CLIENT SIDE ONLY - can be bypassed!',
        'function checkFile(file) {',
        '  if (!file.name.endsWith(\'.png\')) {',
        '    alert(\'Only PNG allowed!\');',
        '    return false;',
        '  }',
        '  return true;',
        '}',
        '',
        '// server.php - NO VALIDATION!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename); // No check!',
        '?>',
        '// Attacker uses Burp to change filename to shell.php after browser check',
        ],
        'impact' => 'Attacker bypasses browser check with Burp and uploads PHP shell. Gets RCE. Client-side checks are never secure.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Keep client check for good UX, but always add server check. Server is the real security gate.',
        '<strong>Rule:</strong> Client validation is optional, server validation is mandatory.',
        ],
        'code' => [
        '// SECURE - Server side check mandatory',
        '<?php',
        '$allowed = [\'png\',\'jpg\',\'jpeg\'];',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, $allowed)) { die(\'Invalid type\'); }',
        '',
        '$finfo = finfo_open(FILEINFO_MIME_TYPE);',
        '$mime = finfo_file($finfo, $_FILES[\'file\'][\'tmp_name\']);',
        'if (!in_array($mime, [\'image/png\',\'image/jpeg\'])) { die(\'Invalid MIME\'); }',
        '',
        '$newName = bin2hex(random_bytes(8)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Keep client JS check for user experience',
        'Add server side whitelist check - mandatory',
        'Check MIME with finfo_file()',
        'Randomize filename',
        'Store outside web root if possible',
        'Disable PHP in uploads folder',
        ],
    ],
];

// What js/checker.js lets through: exactly one type, and only in the browser.
$browserAllows = ['png'];

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

            if (in_array($ext, $browserAllows, true)) {
                $flash = [
                    'kind'  => 'fail',
                    'title' => 'Not solved yet',
                    'body'  => $safeName . ' passed the browser check. Change the request in Burp and send a rejected file.',
                ];
            } else {
                $flash = [
                    'kind'  => 'ok',
                    'title' => 'Congratulations! You solved Scenario 02.',
                    'body'  => 'The browser rejected ' . $safeName . ', but the server accepted it.',
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
        <span class="num">File Upload · SCENARIO 02 · UPLOAD</span>
        <h1>Client-Side Validation Bypass</h1>
        <p>Browser JS blocks .php, but server doesn't. Intercept with Burp and change filename.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <form action="" method="POST" enctype="multipart/form-data" id="uploadForm">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
            <p class="notice error" id="errorMsg" aria-live="polite" hidden></p>
            <p class="notice ok" id="uploadtext" aria-live="polite" hidden></p>
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
<script src="js/checker.js?v=2"></script>
</body>
</html>
