<?php
// File Upload · Scenario 28 — IIS web.config Override
// Intended flaw: allows web.config upload which maps .jpg to PHP
$pageTitle = 'Web Shell Upload via IIS web.config Override';
$scenarioNumber = 28;
$nextScenario = sprintf('../scenario%02d/', 29);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);

$labDescription = [
    'IIS allows web.config to map custom extensions to handlers. Upload web.config that maps .jpg to PHP/ASP handler, then upload shell.jpg with PHP code.',
    'Standard: web.config Bypass / IIS Handler Mapping (PortSwigger). Two-step attack.',
];
$labHint = [
    'Step 1 - Burp Suite: Create web.config with payload: <?xml version="1.0"?><configuration><system.webServer><handlers><add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule" scriptProcessor="C:\\PHP\\php-cgi.exe" resourceType="File" /></handlers></system.webServer></configuration>',
    'In Burp Proxy, upload web.config via POST /scenario28/. Intercept and ensure filename is exactly web.config (lowercase).',
    'Server returns 202 \'web.config uploaded\' - mapping is now active.',
    'Step 2 - Create shell.jpg with <?php echo \'pwned\'; ?>',
    'Upload shell.jpg via second POST. Server now treats .jpg as PHP due to web.config handler.',
    'Click link to shell.jpg - it should execute as PHP. Congratulations!',
    'PortSwigger: \'Web shell upload via web.config\'. Use Repeater for both steps.',
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
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><label for="fileToUpload">Select a file:</label><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>" role="status"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
