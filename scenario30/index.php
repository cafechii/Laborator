<?php
// File Upload · Scenario 30 — Trailing Dot/Space Bypass
// Windows strips trailing dot/space
$pageTitle = 'Web Shell Upload via Windows Trailing Dot/Space Bypass';
$scenarioNumber = 30;
$nextScenario = sprintf('../scenario%02d/', 31);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'Windows file system strips trailing dots and spaces from filename.',
    'File named shell.php. or shell.php with space at end is saved as shell.php and executed.',
    'Validation may block .php but not .php. (with dot).',
    'This is Windows Only.',
    'Goal: Upload shell.php. with trailing dot.',
];
$labHint = [
    'This lab works only on Windows.',
    'Create file shell.php. with dot at end.',
    'Or: shell.php with space at end - Windows Explorer blocks it but Burp allows.',
    'Open Burp Suite, Intercept ON, upload shell.php.',
    'Send to Repeater and change filename to shell.php. (with dot).',
    'Or: filename="shell.php " (with space).',
    'Content: <?php echo \'pwned\'; ?>',
    'Click Send. Filter sees .php. (not .php) but Windows strips dot and saves as shell.php.',
    'Click link to execute.',
    'Standard: Trailing Dot/Space Bypass.',
];

$labRootCause = [
    'cwe' => 'CWE-434: Trailing Dot Bypass',
    'owasp' => 'OWASP: Windows Trailing Dot/Space',
    'bad' => [
        'explanation' => [
        '<strong>Programmer blocked .php but forgot Windows strips trailing dots and spaces.</strong> On Windows, file named shell.php. (with dot at end) is saved as shell.php. Validation sees .php. (with dot) not .php, so allows it, but Windows strips dot and saves as shell.php.',
        '<strong>Mistake:</strong> Checked extension exactly, but Windows file system automatically removes trailing dots and spaces. shell.php. -> shell.php, shell.php<space> -> shell.php.',
        '<strong>Why it happens:</strong> Developer tested on Linux (keeps trailing dot) but server runs on Windows (strips dot). Windows Only.',
        ],
        'code' => [
        '// VULNERABLE - Forgets Windows trailing dot!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // shell.php.',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if ($ext == \'php\') { die(\'PHP blocked\'); }',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        '// On Windows: shell.php. is saved as shell.php! Trailing dot stripped!',
        '?>',
        '// Attacker: filename = shell.php. - Validation sees php. not php, allowed, but Windows saves as shell.php - RCE! Windows Only',
        ],
        'impact' => 'Attacker uses trailing dot or space like shell.php. or shell.php<space> to bypass extension check on Windows. Windows strips trailing dot/space and saves as shell.php, gets RCE. Windows Only.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Trim trailing dots, spaces, and slashes from filename before validation. Reject filenames ending with dot or space. Use basename and whitelist.',
        '<strong>Rule:</strong> Normalize filename by trimming trailing dots/spaces.',
        ],
        'code' => [
        '// SECURE - Trim trailing dots and spaces',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$filename = rtrim($filename, \'. /\\\\\'); // Remove trailing . space / \\',
        'if (preg_match(\'/[\\. ]+$/\', $_FILES[\'file\'][\'name\'])) { die(\'Trailing dot/space not allowed\'); }',
        '$filename = basename($filename);',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Trim trailing dots, spaces, slashes from filename with rtrim()',
        'Reject filenames ending with dot or space',
        'Use basename() to get only filename',
        'Whitelist allowed extensions',
        'Randomize filename - eliminates trailing dot bypass',
        'Use Linux server if possible - Linux keeps trailing dot, Windows strips',
        'Disable PHP execution in uploads',
        'Check filename with regex for trailing dot/space: /[\\. ]+$/',
        ],
    ],
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
        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Windows Only</strong>
        </div>
<div class="panel upload-form"><h2>Upload an Image!</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" id="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next scenario &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
