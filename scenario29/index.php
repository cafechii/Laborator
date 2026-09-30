<?php
// File Upload · Scenario 29 — .user.ini Auto-Prepend
$pageTitle = 'Web Shell Upload via .user.ini Auto-Prepend (PHP-FPM)';
$scenarioNumber = 29;
$nextScenario = sprintf('../scenario%02d/', 30);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'PHP-FPM reads .user.ini file in current directory.',
    'Setting auto_prepend_file = shell.jpg makes every PHP file include your shell.',
    'Upload .user.ini with auto_prepend_file, then upload shell.jpg with PHP code.',
    'Then request any PHP file in same folder, it will include shell.',
    'Goal: Upload .user.ini and shell.jpg',
];
$labHint = [
    'Create file .user.ini with content: auto_prepend_file = shell.jpg or auto_prepend_file = ./uploads/shell.jpg',
    'Upload .user.ini via form. Filename must be exactly .user.ini',
    'Server returns 202 - .user.ini is active.',
    'Now create shell.jpg with <?php echo \'pwned\'; ?>',
    'Upload shell.jpg.',
    'Now request any PHP file in same directory, like /scenario29/index.php - it will include shell.jpg before running.',
    'Or request /scenario29/uploads/shell.jpg if it is parsed as PHP via .user.ini.',
    'Standard: .user.ini Injection / PHP Auto Prepend.',
];

$labRootCause = [
    'cwe' => 'CWE-434: .user.ini Injection',
    'owasp' => 'OWASP: PHP Config Injection',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed .user.ini upload.</strong> PHP-FPM reads .user.ini in current directory and applies auto_prepend_file directive which includes attacker file in every PHP execution.',
        '<strong>Mistake:</strong> Did not block .user.ini. PHP with user_ini.filename enabled reads .user.ini from uploads folder. Attacker sets auto_prepend_file = shell.jpg, then shell.jpg is included in every PHP file in same directory.',
        '<strong>Why it happens:</strong> Developer did not know PHP-FPM supports .user.ini per-directory config.',
        ],
        'code' => [
        '// VULNERABLE - Allows .user.ini!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // .user.ini',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        '?>',
        '# Attacker uploads .user.ini with:',
        '# auto_prepend_file = shell.jpg',
        '# Then uploads shell.jpg with <?php system($_GET[\'cmd\']); ?>',
        '# Now every PHP file in same directory includes shell.jpg before running! RCE!',
        ],
        'impact' => 'Attacker uploads .user.ini with auto_prepend_file to include shell.jpg in every PHP execution. Gets RCE when any PHP file in same folder is requested. PHP-FPM feature.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block .user.ini and other PHP config files. Disable user_ini.filename in php.ini or set user_ini.filename to empty. Store uploads outside PHP execution directory.',
        '<strong>Rule:</strong> Never allow PHP config files upload.',
        ],
        'code' => [
        '// SECURE - Block .user.ini',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$blocked = [\'.user.ini\',\'.htaccess\',\'web.config\',\'.htpasswd\'];',
        'if (in_array(strtolower($filename), $blocked)) { die(\'Config file not allowed\'); }',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if ($ext == \'ini\' || $ext == \'\') { die(\'Invalid\'); }',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid ext\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        '; php.ini secure:',
        '; user_ini.filename = ; (empty = disable .user.ini)',
        ],
        'steps' => [
        'Block .user.ini, .htaccess, web.config',
        'Disable .user.ini in php.ini: user_ini.filename = (empty)',
        'Or set open_basedir to restrict PHP file access',
        'Store uploads outside web root or outside PHP execution path',
        'Use whitelist for extensions',
        'Randomize filename',
        'Disable auto_prepend_file and auto_append_file in php.ini for uploads dir',
        'Set php_flag engine off in uploads .htaccess',
        ],
    ],
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error '.(int)$file['error']];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        // Isolation
        if (stripos($safeName, '%00') !== false || strpos($safeName, "\0") !== false) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Null byte detected. Use .user.ini technique.'];
        } elseif (preg_match('/\.php\./i', $safeName)) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Double extension detected. Use .user.ini.'];
        } elseif (strpos($safeName, ';') !== false) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Semicolon detected. Use .user.ini.'];
        } elseif (preg_match('/\.php[\. ]+$/i', $safeName)) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Trailing dot/space detected. Use .user.ini.'];
        } elseif ($ext === 'php') {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'.php blocked. Use .user.ini technique.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Could not save.'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $userIni = $uploadsDir.'/.user.ini';
            if (strtolower($safeName) === '.user.ini') {
                http_response_code(202);
                $linkLabel = 'View .user.ini';
                $flash = ['kind'=>'info','title'=>'.user.ini uploaded','body'=>'Now upload a .jpg file with PHP that will be auto-prepended.'];
            } else {
                $hasPrepend = false;
                if (is_file($userIni)) {
                    $c = file_get_contents($userIni);
                    if (stripos($c, 'auto_prepend_file') !== false && stripos($c, '.jpg') !== false) $hasPrepend = true;
                }
                if ($hasPrepend && $ext === 'jpg') {
                    $fc = file_get_contents($uploadsDir.'/'.$safeName);
                    if (stripos($fc, '<?php') !== false) {
                        $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 29.','body'=>$safeName.' will be auto-prepended via .user.ini'];
                    } else {
                        $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'No PHP code in file.'];
                    }
                } else {
                    $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'Upload .user.ini with auto_prepend_file first.'];
                }
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 29 · UPLOAD</span><h1>.user.ini Auto-Prepend</h1><p>PHP .user.ini sets auto_prepend_file to JPG. Upload .user.ini then shell.jpg via Burp.</p>
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
