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
    'Apache allows .htaccess file to override server config.',
    'Uploading .htaccess with AddType application/x-httpd-php .jpg makes .jpg run as PHP.',
    'This works only on Apache with AllowOverride enabled.',
    'This is Linux/Apache Only.',
    'Goal: Upload .htaccess then upload shell.jpg',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'This lab works only on Apache with .htaccess enabled.',
    'Create file .htaccess with content: AddType application/x-httpd-php .jpg',
    'Upload .htaccess via form. Filename must be exactly .htaccess.',
    'Server returns 202 - .htaccess is active.',
    'Now create shell.jpg with <?php echo \'pwned\'; ?>',
    'Upload shell.jpg - because .htaccess maps .jpg to PHP, it will run.',
    'Click link to execute.',
    'Standard: .htaccess Override / Apache Config Injection.',
];

$labRootCause = [
    'cwe' => 'CWE-434: htaccess Override',
    'owasp' => 'OWASP: Apache Config Injection',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed .htaccess upload on Apache server.</strong> .htaccess can override Apache config with AddType to make .jpg run as PHP.',
        '<strong>Mistake:</strong> Did not block .htaccess file. Apache with AllowOverride All allows .htaccess to change config. Attacker uploads .htaccess with AddType application/x-httpd-php .jpg, then uploads shell.jpg with PHP code, and .jpg runs as PHP.',
        '<strong>Why it happens:</strong> Developer did not know .htaccess can override server config. This is Linux/Apache Only.',
        ],
        'code' => [
        '// VULNERABLE - Allows .htaccess!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // .htaccess',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        '?>',
        '# Attacker uploads .htaccess with:',
        '# AddType application/x-httpd-php .jpg',
        '# Now Apache treats .jpg as PHP!',
        '# Then attacker uploads shell.jpg with <?php system($_GET[\'cmd\']); ?>',
        '# Request /uploads/shell.jpg - Apache runs it as PHP! RCE!',
        ],
        'impact' => 'Attacker uploads .htaccess to make .jpg run as PHP, then uploads shell.jpg with PHP code and gets RCE. Apache Only with AllowOverride enabled.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block .htaccess and other config files like .htpasswd, .user.ini, web.config. Disable AllowOverride or set AllowOverride None for uploads folder.',
        '<strong>Rule:</strong> Never allow config files upload.',
        ],
        'code' => [
        '// SECURE - Block .htaccess',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$blocked = [\'.htaccess\',\'.htpasswd\',\'.user.ini\',\'web.config\'];',
        'if (in_array(strtolower($filename), $blocked)) { die(\'Config file not allowed\'); }',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if ($ext == \'htaccess\' || $ext == \'\') { die(\'Invalid\'); }',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid ext\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        '# Apache config secure:',
        '# <Directory /var/www/uploads>',
        '#   AllowOverride None',
        '#   php_flag engine off',
        '# </Directory>',
        ],
        'steps' => [
        'Block .htaccess, .htpasswd, .user.ini, web.config',
        'Block files with no extension or starting with dot',
        'Set AllowOverride None for uploads folder in Apache config',
        'Disable PHP execution in uploads: php_flag engine off',
        'Store uploads outside web root',
        'Use whitelist for extensions',
        'Randomize filename',
        ],
    ],
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
        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Linux / Apache Only</strong>
        </div>

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
