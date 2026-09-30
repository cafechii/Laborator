<?php
// File Upload · Scenario 28 — IIS web.config Override
// Intended flaw: allows web.config upload which maps .jpg to PHP
$pageTitle = 'Web Shell Upload via IIS web.config Override';
$scenarioNumber = 28;
$nextScenario = sprintf('../scenario%02d/', 29);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);

$labDescription = [
    'IIS allows web.config file to map custom extensions to handlers.',
    'Upload web.config that maps .jpg to PHP or ASP handler, then upload shell.jpg.',
    'This works only on Windows IIS.',
    'This is Windows/IIS Only.',
    'Goal: Upload web.config then shell.jpg',
];
$labHint = [
    'This lab works only on Windows IIS.',
    'Create file web.config with: <?xml version="1.0"?><configuration><system.webServer><handlers><add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule" scriptProcessor="C:\\PHP\\php-cgi.exe" /></handlers></system.webServer></configuration>',
    'Upload web.config via form. Filename must be exactly web.config.',
    'Server returns 202 - web.config is active.',
    'Now create shell.jpg with <?php echo \'pwned\'; ?>',
    'Upload shell.jpg - because web.config maps .jpg to PHP, it will run.',
    'Click link to execute.',
    'Standard: IIS web.config Override.',
];

$labRootCause = [
    'cwe' => 'CWE-434: web.config Override',
    'owasp' => 'OWASP: IIS Config Injection',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed web.config upload on IIS server.</strong> web.config is IIS config file, similar to .htaccess for Apache. Can map .jpg to run as PHP or ASP.',
        '<strong>Mistake:</strong> Did not block web.config file. IIS with web.config allows <handlers> to map *.jpg to FastCgiModule with PHP handler. Attacker uploads web.config that makes .jpg run as PHP, then uploads shell.jpg with PHP code.',
        '<strong>Why it happens:</strong> Developer did not know web.config can override IIS handler mapping. This is Windows/IIS Only.',
        ],
        'code' => [
        '// VULNERABLE - Allows web.config!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // web.config',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        '?>',
        '<!-- Attacker uploads web.config with: -->',
        '<!-- AddType for IIS: <add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule" /> -->',
        '<!-- Now IIS treats *.jpg as PHP! -->',
        '<!-- Then attacker uploads shell.jpg with PHP code and gets RCE! Windows/IIS Only -->',
        ],
        'impact' => 'Attacker uploads web.config to make .jpg run as PHP on IIS, then uploads shell.jpg with PHP code and gets RCE. IIS config injection. Windows/IIS Only.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block web.config and other IIS config files. Disable overriding handlers in uploads folder. Set handler mapping only in main config, not allow override.',
        '<strong>Rule:</strong> Never allow IIS config files upload.',
        ],
        'code' => [
        '// SECURE - Block web.config',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$blocked = [\'web.config\',\'.htaccess\',\'.htpasswd\',\'.user.ini\'];',
        'if (in_array(strtolower($filename), $blocked)) { die(\'Config file not allowed\'); }',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if ($ext == \'config\' || $ext == \'\') { die(\'Invalid\'); }',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid ext\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Block web.config, .htaccess, .user.ini, and other config files',
        'Block files with no extension or config extension',
        'Set overrideMode="Deny" for uploads folder in IIS applicationHost.config',
        'Disable handler mapping override in uploads',
        'Store uploads outside web root',
        'Use whitelist for extensions',
        'Randomize filename',
        'Disable PHP/ASP execution in uploads folder if possible',
        ],
    ],
];

$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error code '.(int)$file['error']];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        // Isolation: block other bypass techniques from solving this lab
        if (stripos($safeName, '%00') !== false || strpos($safeName, "\0") !== false) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Null byte detected. This lab is about web.config, not null byte.'];
        } elseif (preg_match('/\.php\./i', $safeName)) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Double extension detected. This lab requires web.config mapping, not double extension.'];
        } elseif (strpos($safeName, ';') !== false) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Semicolon detected. Use web.config technique.'];
        } elseif (preg_match('/\.php[\. ]+$/i', $safeName) || preg_match('/\.php%20$/i', $safeName)) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Trailing dot/space detected. Use web.config.'];
        } elseif ($ext === 'php') {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>' .php is blocked. Upload web.config first.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Could not save file.'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $webConfig = $uploadsDir.'/web.config';
            if (strtolower($safeName) === 'web.config') {
                http_response_code(202);
                $linkLabel = 'View web.config';
                $flash = ['kind'=>'info','title'=>'web.config uploaded','body'=>'Now upload a .jpg file containing PHP code that will be mapped to executable.'];
            } else {
                $hasMapping = false;
                if (is_file($webConfig)) {
                    $content = file_get_contents($webConfig);
                    if (stripos($content, '.jpg') !== false && (stripos($content, 'php') !== false || stripos($content, 'FastCgiModule') !== false || stripos($content, 'handler') !== false)) {
                        $hasMapping = true;
                    }
                }
                if ($hasMapping && $ext === 'jpg') {
                    $fileContent = file_get_contents($uploadsDir.'/'.$safeName);
                    if (stripos($fileContent, '<?php') !== false || stripos($fileContent, '<?=') !== false) {
                        $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 28.','body'=>$safeName.' is mapped to PHP via web.config.'];
                    } else {
                        $flash = ['kind'=>'fail','title'=>'Not solved yet','body'=>'File saved but does not contain PHP code.'];
                    }
                } else {
                    $flash = ['kind'=>'fail','title'=>'Not solved yet','body'=>'Upload web.config with .jpg mapping first, then upload .jpg with PHP.'];
                }
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 28 · UPLOAD</span><h1>IIS web.config Override</h1><p>IIS web.config maps .jpg to PHP. Upload web.config then shell.jpg via Burp - two-step.</p>
        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Windows / IIS Only</strong>
        </div>
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><label for="fileToUpload">Select a file:</label><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>" role="status"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
