<?php
// File Upload · Scenario 29 — .user.ini Auto-Prepend
$pageTitle = 'Web Shell Upload via .user.ini Auto-Prepend (PHP-FPM)';
$scenarioNumber = 29;
$nextScenario = sprintf('../scenario%02d/', 30);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'PHP-FPM respects .user.ini in current directory. Setting auto_prepend_file = shell.jpg makes every PHP file include shell.jpg as PHP.',
    'Standard: .user.ini Bypass / PHP Auto-Prepend (PortSwigger). Two-step: .user.ini + shell.jpg',
];
$labHint = [
    'Step 1 - Create .user.ini with: auto_prepend_file = shell.jpg or auto_prepend_file = ./shell.jpg',
    'In Burp Suite, upload .user.ini via POST /scenario29/. Use Proxy > Intercept to ensure filename is .user.ini (dotfile).',
    'Server returns 202 info - .user.ini is now active in uploads/ dir.',
    'Step 2 - Create shell.jpg with <?php echo \'pwned\'; ?>',
    'Upload shell.jpg via second request.',
    'Now any PHP file in that directory will prepend shell.jpg. Access any existing PHP file or upload index.php that will include it.',
    'In lab, after both uploads, accessing shell.jpg or any PHP file executes prepended code. Click link for Congratulations.',
    'PortSwigger: \'Web shell upload via .user.ini\'.',
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
