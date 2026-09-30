<?php
// File Upload · Scenario 30 — Trailing Dot/Space Bypass
// Windows strips trailing dot/space
$pageTitle = 'Web Shell Upload via Windows Trailing Dot/Space Bypass';
$scenarioNumber = 30;
$nextScenario = sprintf('../scenario%02d/', 31);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'Windows filesystem strips trailing dots and spaces. shell.php. or shell.php<space> is saved as shell.php and executed.',
    'Filter blocks .php but not .php. or .php%20.',
    'Standard: Trailing Dot/Space Bypass / Windows Filename Bypass (WSTG). Goal: shell.php. or shell.php%20',
];
$labHint = [
    'In Burp Suite, turn Intercept ON.',
    'Upload shell.php - blocked with \' .php is blocked. Try trailing dot\'.',
    'Send POST /scenario30/ to Repeater.',
    'Change filename to shell.php. (trailing dot) or shell.php%20 (encoded space) or shell.php%2e or shell.php /',
    'Content: <?php echo \'pwned\'; ?>',
    'Send. Server sees .php. (not .php) so bypasses blacklist, but Windows strips trailing dot and saves as shell.php.',
    'Lab simulates Windows stripping via rtrim(). Click link to execute.',
    'PortSwigger: \'Web shell upload via trailing dot\'. Try both dot and %20.',
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error '.(int)$file['error']];
    } else {
        $origName = $file['name'];
        $safeName = basename($origName);
        // Isolation: block other bypass techniques, allow only trailing dot/space
        $isolationBlocked = false;
        if (stripos($safeName, '%00') !== false || strpos($safeName, "\0") !== false) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Null byte not allowed. Use trailing dot.']; http_response_code(422); }
        elseif (strpos($safeName, ';') !== false) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Semicolon not allowed. Use trailing dot.']; http_response_code(422); }
        elseif (preg_match('/\.php\.(?:jpg|jpeg|png|gif)$/i', $safeName)) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Double extension not allowed. Use trailing dot.']; http_response_code(422); }
        elseif (preg_match('/\.php5|\.phtml|\.phar/i', $safeName)) { $isolationBlocked = true; $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Alt extension not allowed. Use trailing dot.']; http_response_code(422); }

        if (!$isolationBlocked) {
            // Detect bypass before any blocking: trailing dot, space, slash, %20, %2e
            $hadBypass = preg_match('/\.php(?:[\. \/]|%20|%2e|%00)+$/i', $origName) || preg_match('/\.php\.$/', $safeName) || preg_match('/\.php\s+$/', $safeName);
            // Simulate Windows stripping: trim trailing dots, spaces, slashes, and URL-encoded variants
            $stripped = $safeName;
            $stripped = preg_replace('/(?:%20|%2e|%00)+$/i', '', $stripped);
            $stripped = rtrim($stripped, ". /\\");
            $stripped = rtrim($stripped);
            $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
            $extStripped = strtolower(pathinfo($stripped, PATHINFO_EXTENSION));
            // Block exact .php only if no bypass chars were present
            if (!$hadBypass && $ext === 'php') {
                $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'.php is blocked. Try trailing dot/space like shell.php. or shell.php%20'];
                http_response_code(422);
            } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$stripped)) {
                $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Could not save.'];
            } else {
                $link = 'uploads/'.rawurlencode($stripped);
                $linkLabel = 'Open '.$stripped;
                $fc = file_get_contents($uploadsDir.'/'.$stripped);
                if ($hadBypass && strtolower(pathinfo($stripped, PATHINFO_EXTENSION)) === 'php' && stripos($fc, '<?php') !== false) {
                    $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 30.','body'=>'Trailing dot/space bypass worked: '.$origName.' saved as '.$stripped];
                } elseif (strtolower(pathinfo($stripped, PATHINFO_EXTENSION)) === 'php') {
                    $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'File saved as PHP but no PHP code.'];
                    http_response_code(422);
                } else {
                    $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'Use trailing dot/space like shell.php.'];
                    http_response_code(422);
                }
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 30 · UPLOAD</span><h1>Trailing Dot/Space Bypass</h1><p>Windows strips trailing dot/space. Bypass .php filter with shell.php. using Burp Repeater.</p>
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
