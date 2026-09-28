<?php
// File Upload · Scenario 18 — Server Config Upload (.htaccess)
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via .htaccess Override';
$scenarioNumber = 18;
$nextScenario = sprintf('../scenario%02d/', 19);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Apache allows .htaccess to override config. Uploading .htaccess with AddType application/x-httpd-php .jpg makes .jpg execute as PHP.',
    'Standard: .htaccess Bypass / Apache Config Upload (PortSwigger). Goal: Upload .htaccess then shell.jpg',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Step 1: Create .htaccess with: AddType application/x-httpd-php .jpg or <FilesMatch ".jpg"> SetHandler application/x-httpd-php </FilesMatch>',
    'In Burp Proxy, upload .htaccess file. Intercept POST /scenario18/ and ensure filename is .htaccess (no extension filter).',
    'Server should accept .htaccess and return 202 info.',
    'Step 2: Create shell.jpg with <?php echo \'pwned\'; ?>',
    'Upload shell.jpg via form (second request).',
    'Server will now treat .jpg as PHP due to .htaccess mapping. Click link to execute.',
    'This is exactly PortSwigger Lab: \'Web shell upload via .htaccess\'.',
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
        $safeName = basename($file['name']);
        $ext      = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

        if ($ext === 'php') {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'The .php extension is blocked. Upload the server configuration first.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The server could not save the file.'];
        } else {
            $link = 'uploads/' . rawurlencode($safeName);
            $rulesFile = $uploadsDir . '/.htaccess';

            if (strtolower($safeName) === '.htaccess') {
                // Configuration is a prerequisite, not the final win. Keep the
                // response at 202, but show it as a clear intermediate step.
                http_response_code(202);
                $linkLabel = 'View the uploaded .htaccess';
                $flash = ['kind' => 'info', 'title' => 'Configuration uploaded',
                          'body'  => 'The .htaccess file is saved. Now upload a PHP file with the extension it defines.'];
            } else {
                $declaredExt = null;
                if (is_file($rulesFile)) {
                    $rules = (string) file_get_contents($rulesFile);
                    if (preg_match('/AddType\s+application\/x-httpd-php\s+\.([a-z0-9]+)\b/i', $rules, $ruleMatch)) {
                        $declaredExt = strtolower($ruleMatch[1]);
                    }
                }

                if ($declaredExt !== null && $ext === $declaredExt) {
                    $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 18.',
                              'body'  => $safeName . ' uses the custom extension defined in .htaccess.'];
                } else {
                    $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                              'body'  => 'The file was saved, but its extension is not enabled by .htaccess.'];
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
        <span class="num">File Upload · SCENARIO 18 · UPLOAD</span>
        <h1>.htaccess Override</h1>
        <p>Upload .htaccess to map .jpg to PHP, then upload shell.jpg. Two-step bypass with Burp.</p>

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
