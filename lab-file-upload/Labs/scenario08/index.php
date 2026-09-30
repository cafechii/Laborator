<?php
// File Upload · Scenario 08 — Double Extension
$pageTitle = 'Web Shell Upload via Double Extension Bypass';
$scenarioNumber = 8;
$nextScenario = sprintf('../scenario%02d/', 9);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'The server checks only the last extension (e.g., .png) but Apache executes file if it contains .php anywhere (e.g., shell.php.png).',
    'This is classic Apache double extension behavior + weak validation.',
    'Standard: Double Extension Bypass. Goal: Upload shell.php.png',
];
$labHint = [
    'Open Burp Suite > Proxy > Intercept OFF initially, just upload shell.php.png with PHP code.',
    'If blocked, turn Intercept ON and send to Repeater.',
    'Filename must be exactly shell.php.png (lowercase .php followed by .png).',
    'The server checks final extension .png (allowed), but Apache handler sees .php and executes as PHP.',
    'Payload: <?php echo \'pwned\'; ?>',
    'Send request. Should get Congratulations. Click link - if Apache configured, it executes.',
    'This is PortSwigger: \'Web shell upload via double extension\'. Isolated: trailing dot and null byte will NOT work here.',
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error '.(int)$file['error']];
    } else {
        $safeName = basename($file['name']);
        // Isolation: block other bypass techniques
        $isolationBlocked = false;
        if (stripos($safeName, '%00') !== false || strpos($safeName, "\0") !== false) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Null byte not allowed in double extension lab.']; http_response_code(422); }
        elseif (strpos($safeName, ';') !== false) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Semicolon not allowed. Use double extension.']; http_response_code(422); }
        elseif (preg_match('/\.php[\. ]+$/i', $safeName) || preg_match('/%20$/i', $safeName)) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Trailing dot/space not allowed. Use double extension like .php.png']; http_response_code(422); }
        elseif (preg_match('/\.php5|\.phtml|\.phar|\.pht/i', $safeName)) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Alt extension not allowed. Use .php.png']; http_response_code(422); }

        if (!$isolationBlocked) {
            $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
            if ($ext === 'php') {
                $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'The final .php extension is blocked. Use a double extension.'];
                http_response_code(422);
            } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
                $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Could not save.'];
            } else {
                $link = 'uploads/'.rawurlencode($safeName);
                if (preg_match('/\.php\.(?:jpg|jpeg|png|gif)$/i', $safeName)) {
                    $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 08.','body'=>$safeName.' passed because its name contains .php before the final extension.'];
                } else {
                    $flash = ['kind'=>'fail','title'=>'Not solved yet','body'=>$safeName.' was saved, but it does not contain .php before the final extension.'];
                    http_response_code(422);
                }
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 08 · UPLOAD</span><h1>Double Extension Bypass</h1><p>Server checks final .png, Apache executes inner .php. Upload shell.php.png.</p>
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><label for="fileToUpload">Select a file:</label><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
