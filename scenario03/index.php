<?php
// File Upload · Scenario 03 — server-side MIME type validation bypass
//
// Intended flaw: the check reads $_FILES['fileToUpload']['type'], which is the
// Content-Type the CLIENT wrote into the multipart body. It is never compared
// with the real bytes, so declaring an allowed image type is enough.
// Path traversal is neutralized with basename() to keep this a ONE-bug lab.

$pageTitle = 'Web Shell Upload via Content-Type Bypass';
$scenarioNumber = 3;
$nextScenario = sprintf('../scenario%02d/', 4);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// The whitelist, exactly as the lab description states it.
$allowedMime = ['image/jpeg', 'image/png', 'image/gif'];

// Isolated: only .php (not alternatives) should solve this MIME bypass lab
$executableExt = ['php'];

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'The server checks MIME type using Content-Type header from client.',
    'This header is controlled by you and can be changed.',
    'Standard name: MIME Type Bypass / Content-Type Spoofing.',
    'Goal: Upload PHP file with image Content-Type.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Open Burp Suite, turn Proxy > Intercept ON.',
    'Create shell.php with <?php echo \'pwned\'; ?> and upload it.',
    'Burp catches POST to /scenario03/. Send it to Repeater (Ctrl+R).',
    'In Repeater, find Content-Type: application/octet-stream or text/php.',
    'Change it to Content-Type: image/png (allowed types are image/jpeg, image/png, image/gif).',
    'Keep filename as shell.php. Do not change extension.',
    'Click Send. You should get Congratulations.',
    'Click the link to run it. Standard: Content-Type Bypass.',
];

$labRootCause = [
    'cwe' => 'CWE-434: MIME Type Spoofing',
    'owasp' => 'OWASP: Content-Type Bypass',
    'bad' => [
        'explanation' => [
        '<strong>Programmer checked Content-Type header from client ($_FILES[\'type\']).</strong> This header is controlled by attacker and can be changed.',
        '<strong>Mistake:</strong> Used $_FILES[\'file\'][\'type\'] which comes from browser. Attacker can set it to image/png while uploading shell.php.',
        '<strong>Why it happens:</strong> Developer did not know that Content-Type header is user input, not real file type.',
        ],
        'code' => [
        '// VULNERABLE - Trusts client Content-Type!',
        '<?php',
        '$type = $_FILES[\'file\'][\'type\']; // Client controlled! Can be spoofed!',
        'if ($type != \'image/png\' && $type != \'image/jpeg\') {',
        '  die(\'Only images allowed\');',
        '}',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '?>',
        '// Attacker sends: Content-Type: image/png but file is shell.php with PHP code',
        '// Server sees image/png and allows it, but file is PHP and runs!',
        ],
        'impact' => 'Attacker spoofs Content-Type to image/png and uploads PHP shell. Gets RCE. Content-Type header is not trustworthy.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Don\'t use $_FILES[\'type\']. Use server-side MIME detection with finfo_file() which reads real file content.',
        '<strong>Rule:</strong> Client headers are never trusted for security.',
        ],
        'code' => [
        '// SECURE - Use finfo to check real MIME',
        '<?php',
        '$finfo = finfo_open(FILEINFO_MIME_TYPE);',
        '$realMime = finfo_file($finfo, $_FILES[\'file\'][\'tmp_name\']); // Reads file content',
        '$allowedMime = [\'image/png\',\'image/jpeg\',\'image/gif\'];',
        'if (!in_array($realMime, $allowedMime)) {',
        '  die(\'Invalid file type - real MIME is \' . $realMime);',
        '}',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid ext\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Never use $_FILES[\'type\'] - it is client controlled',
        'Use finfo_file() to read real MIME from file content',
        'Also check extension whitelist',
        'Verify with getimagesize() for images',
        'Randomize filename',
        'Disable PHP execution in uploads',
        ],
    ],
];

$message = null;
$link    = null;
$flash   = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $message = 'Upload failed (error code ' . (int) $file['error'] . ').';
        $flash   = [
            'kind'  => 'fail',
            'title' => 'Upload failed',
            'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').',
        ];
    } else {
        $declared = (string) $file['type'];

        if (!in_array($declared, $allowedMime, true)) {
            http_response_code(415);
            $flash = [
                'kind'  => 'fail',
                'title' => 'Upload rejected',
                'body'  => 'Change the multipart Content-Type to an allowed image type in Burp.',
            ];
        } else {
            $safeName = basename($file['name']);
            // Isolation: block other bypass techniques from solving MIME lab
            if (stripos($safeName, '%00') !== false || strpos($safeName, "\0") !== false) {
                http_response_code(422);
                $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Null byte not allowed in this MIME bypass lab.'];
            } elseif (preg_match('/\.php\./i', $safeName) || strpos($safeName, ';') !== false || preg_match('/\.php[\. ]+$/i', $safeName) || preg_match('/%20$/i', $safeName)) {
                http_response_code(422);
                $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Use MIME bypass only, not extension tricks.'];
            } else {
                $dest = $uploadsDir . '/' . $safeName;
                $ext  = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

                if (!move_uploaded_file($file['tmp_name'], $dest)) {
                    $message = 'Could not store the file (check uploads/ permissions).';
                    $flash   = [
                        'kind'  => 'fail',
                        'title' => 'Upload failed',
                        'body'  => 'The server could not save the file.',
                    ];
                } else {
                    $link = 'uploads/' . rawurlencode($safeName);

                    if (in_array($ext, $executableExt, true)) {
                        $flash = [
                            'kind'  => 'ok',
                            'title' => 'Congratulations! You solved Scenario 03.',
                            'body'  => 'The server accepted the PHP file with Content-Type ' . $declared . '. Open the link to view the result.',
                        ];
                    } else {
                        http_response_code(422);
                        $flash = [
                            'kind'  => 'fail',
                            'title' => 'Not solved yet',
                            'body'  => $safeName . ' was saved, but it is not a PHP test file.',
                        ];
                    }
                }
            }
        }
    }
}

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
        <span class="num">File Upload · SCENARIO 03 · UPLOAD</span>
        <h1>Content-Type Bypass (MIME Spoofing)</h1>
        <p>Server trusts client-supplied Content-Type. Spoof it to image/png with Burp.</p>

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
                <?php if ($link !== null): ?>
                    <div class="flash-lines">
                        <span>stored as</span> <?= htmlspecialchars($link, ENT_QUOTES) ?>
                        <span>declared type</span> <?= htmlspecialchars((string) $file['type'], ENT_QUOTES) ?>
                        <span>real bytes</span> <?= htmlspecialchars((string) (function_exists('finfo_file') ? finfo_file(finfo_open(FILEINFO_MIME_TYPE), $uploadsDir . '/' . $safeName) : 'n/a'), ENT_QUOTES) ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">
                    Next scenario &rarr;
                </a>
            </div>
        <?php endif; ?>

        <?php if ($message !== null): ?>
            <p class="notice error"><?= htmlspecialchars($message, ENT_QUOTES) ?></p>
        <?php endif; ?>
        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>">See the image!</a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
