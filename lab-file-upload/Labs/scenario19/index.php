<?php
// File Upload · Scenario 19 — Nested Extension Stripping
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via Nested Extension Stripping';
$scenarioNumber = 19;
$nextScenario = sprintf('../scenario%02d/', 20);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Server does single-pass blacklist removal: str_replace(\'.php\',\'\',filename). So .p.phphp becomes .php after one strip.',
    'Standard: Nested Extension Bypass / Recursive Stripping. Goal: shell.p.phphp or shell.php.php',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Open Burp Suite > Proxy > Intercept ON.',
    'Upload shell.php - blocked and stripped.',
    'Send to Repeater. Try filename shell.p.phphp',
    'Server does: \'shell.p.phphp\' -> remove \'.php\' once -> \'shell.php\' -> saved as .php and executes!',
    'Alternatively try shell.php.php or .phtml.phphpp etc.',
    'Content: <?php echo \'pwned\'; ?>',
    'Send and check response. Congratulations when nested bypass works.',
    'PortSwigger: \'Web shell upload via nested extension\'.',
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
        $requested = basename($file['name']);

        if (stripos($requested, '.htaccess') !== false) {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'This lab does not accept .htaccess files.'];
        } else {
            // the flaw: one case-insensitive substitution pass, no loop.
            // A case-only spelling must not become a second solution.
            $stored = preg_replace('/\.php/i', '', $requested, 1);

            if ($stored === '' || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $stored)) {
                $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                          'body'  => 'The server could not save the file.'];
            } else {
                $link = 'uploads/' . rawurlencode($stored);

                if (strtolower(pathinfo($stored, PATHINFO_EXTENSION)) === 'php') {
                    $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 19.',
                              'body'  => 'The sanitizer removed one .php string and left another one.'];
                } else {
                    $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                              'body'  => 'The sanitized filename is not executable. Use a nested .php filename.'];
                }
            }
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
        <span class="num">File Upload · SCENARIO 19 · UPLOAD</span>
        <h1>Nested Extension Stripping</h1>
        <p>Filter strips .php once. Use .p.phphp to reconstruct .php after stripping. Use Burp Repeater.</p>

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
