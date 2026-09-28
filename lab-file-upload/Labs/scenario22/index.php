<?php
// File Upload · Scenario 22 — Path Traversal out of uploads/
//
// Intended flaw: the filename is decoded and joined to the upload path before
// storage. The uploads directory itself does not execute PHP, so the intended
// path traversal is the only way to reach an executable directory.

$pageTitle = 'Path Traversal via File Upload Filename';
$scenarioNumber = 22;
$nextScenario = sprintf('../scenario%02d/', 23);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Filename parameter contains ../ to traverse out of uploads/ to executable directory.',
    'Example: ../../shell.php writes to parent directory.',
    'Standard: Directory Traversal via File Upload (CWE-22). Goal: ../../../tmp/shell.php or ..%2F..%2Fshell.php',
];

// Read by ../menu/navbar.php to fill the hint drawer.
$labHint = [
    'In Burp Suite, turn Intercept ON and upload shell.php.',
    'Send POST /scenario22/ to Repeater.',
    'Change filename to ../../../shell.php or ..%2F..%2F..%2Ftmp%2Fshell.php or %2e%2e%2f%2e%2e%2fshell.php',
    'Content: <?php echo \'pwned\'; ?>',
    'Send. Server does basename()? No, it allows traversal, so file is written outside uploads/.',
    'Check response link - it may show traversal path. Try to GET /shell.php or /tmp/shell.php',
    'PortSwigger: \'File upload via path traversal\'.',
];

$link      = null;
$linkLabel = 'See the file';
$flash     = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                  'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').'];
    } else {
        $requested = urldecode($file['name']);
        $base      = realpath($uploadsDir) ?: $uploadsDir;
        $scenario  = realpath(__DIR__) ?: __DIR__;
        $guess     = $base . '/' . ltrim(str_replace('\\', '/', $requested), '/');
        $resolved  = realpath(dirname($guess)) ?: dirname($guess);

        $scenarioPrefix = rtrim($scenario, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $insideScenario = $resolved === $scenario || strpos($resolved, $scenarioPrefix) === 0;

        if (stripos($requested, '.htaccess') !== false) {
            http_response_code(403);
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'This lab does not accept .htaccess files.'];
        } elseif (!$insideScenario) {
            http_response_code(403);
            $flash = ['kind' => 'fail', 'title' => 'Upload blocked',
                      'body'  => 'The path left the lab directory. Use one level of traversal only.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $guess)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The server could not save the file.'];
        } else {
            $storedName = basename($guess);
            $destDir    = realpath(dirname($guess)) ?: dirname($guess);
            $escaped    = rtrim($destDir, '/') !== rtrim($base, '/');

            if ($escaped) {
                $link      = rawurlencode($storedName);
                $linkLabel = 'Open the file in the scenario folder';
                $flash     = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 22.',
                              'body'  => 'The file was saved outside uploads/ and executed.'];
            } else {
                $link  = 'uploads/' . rawurlencode($storedName);
                $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                          'body'  => 'The file stayed in uploads/, where PHP execution is disabled.'];
            }
        }
    }
}

// Keep the verdict meaningful to the request and the page.
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
        <span class="num">File Upload · SCENARIO 22 · UPLOAD</span>
        <h1>Path Traversal via Filename</h1>
        <p>Filename with ../ escapes uploads/. Use Burp Repeater to traverse and write shell.</p>

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

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
