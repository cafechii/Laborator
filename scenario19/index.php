<?php
// File Upload · Scenario 19 — Nested Extension Stripping
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via Nested Extension Stripping';
$scenarioNumber = 19;
$nextScenario = sprintf('../scenario%02d/', 20);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Server does blacklist removal only once: str_replace(\'.php\',\'\',filename).',
    'So .p.phphp becomes .php after one removal: .p.phphp -> remove .php -> .pphp -> still contains .php? Actually .p.phphp -> p + php = .php',
    'Goal: Use double extension trick to get .php after filter.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Try upload shell.php - blocked.',
    'Try shell.p.phphp - server removes .php once, leaving shell.php.',
    'Create file named shell.p.phphp with <?php echo \'pwned\'; ?>',
    'Upload via form. Use Burp Repeater to test variations: .p.phphp, .phphp, .php.php.',
    'Server does single-pass replace, so after removal you get .php.',
    'Click link to run. Standard: Double Extension Filter Bypass / Recursive Bypass.',
];

$labRootCause = [
    'cwe' => 'CWE-434: Double Extension Filter Bypass',
    'owasp' => 'OWASP: Recursive Filter Bypass',
    'bad' => [
        'explanation' => [
        '<strong>Programmer tried to block .php by removing it once with str_replace(\'.php\',\'\',filename).</strong> But attacker uses .p.phphp which becomes .php after one removal.',
        '<strong>Mistake:</strong> Single-pass blacklist removal. str_replace removes .php once, but .p.phphp becomes .php again. Need recursive or better, whitelist.',
        '<strong>Why it happens:</strong> Developer thought removing .php once is enough, but did not think about nested bypass.',
        ],
        'code' => [
        '// VULNERABLE - Single-pass removal!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // shell.p.phphp',
        '$filename = str_replace(\'.php\', \'\', $filename); // Removes .php once: .p.phphp -> .php!',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename); // Saves as shell.php!',
        '?>',
        '// Attacker: shell.p.phphp -> str_replace removes .php -> shell.php - RCE!',
        ],
        'impact' => 'Attacker uses .p.phphp or .phphp to bypass single-pass filter and gets .php file saved. Gets RCE. Filter must be recursive or whitelist.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Don\'t use blacklist removal. Use whitelist. If must use blacklist, loop until no more .php found, or better, reject if .php appears anywhere.',
        '<strong>Rule:</strong> Whitelist is safer than blacklist removal.',
        ],
        'code' => [
        '// SECURE - Whitelist + reject if php anywhere',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        'if (stripos($filename, \'.php\') !== false) { die(\'PHP not allowed anywhere\'); }',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Only images allowed\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Use whitelist not blacklist',
        'Reject if .php appears anywhere in filename, not just extension',
        'If using blacklist removal, loop recursively until no .php',
        'Better: randomize filename completely',
        'Check MIME with finfo_file()',
        'Disable PHP execution in uploads',
        'Store outside web root',
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
        $requested = basename($file['name']);

        if (stripos($requested, '.htaccess') !== false) {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'This lab does not accept .htaccess files.'];
        } else {
            // the flaw: one case-insensitive substitution pass, no loop.
            // A case-only spelling must not become a second solution.
            $stored = preg_replace('/\.php/i', '', $requested, 1);

            if ($stored === '' || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $stored)) {
                $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                          'body'  => 'The server could not save the file.'];
            } else {
                $link = 'uploads/' . rawurlencode($stored);

                if (strtolower(pathinfo($stored, PATHINFO_EXTENSION)) === 'php') {
                    $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 19.',
                              'body'  => 'The sanitizer removed one .php string and left another one.'];
                } else {
                    $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                              'body'  => 'The sanitized filename is not executable. Use a nested .php filename.'];
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
        <span class="num">File Upload · SCENARIO 19 · UPLOAD</span>
        <h1>Nested Extension Stripping</h1>
        <p>Filter strips .php once. Use .p.phphp to reconstruct .php after stripping. Use Burp Repeater.</p>

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
