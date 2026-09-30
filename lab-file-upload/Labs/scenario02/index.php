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
    'The application validates file extensions only in client-side JavaScript (checker.js).',
    'The server-side does not re-validate the extension.',
    'This is OWASP: Client-Side Validation Bypass. Goal: Bypass browser JS check using Burp.',
];

// Read by ../menu/navbar.php to fill the hint drawer.
$labHint = [
    'Open Burp Suite > Proxy > Intercept > Turn Intercept ON.',
    'In browser, try to upload shell.php - the JS will block it with \'Only PNG allowed\'.',
    'Now select a valid file like image.png and click Upload.',
    'Burp will intercept the POST request to /scenario02/.',
    'In Burp Proxy, look at the multipart body: Content-Disposition contains filename="image.png".',
    'Change filename to shell.php and change file content to <?php echo \'pwned\'; ?>',
    'Forward the request (Ctrl+F). Server will accept it because server-side check is missing.',
    'Click the link to execute your shell. This is PortSwigger Lab: \'Web shell upload via client-side validation bypass\'.',
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
