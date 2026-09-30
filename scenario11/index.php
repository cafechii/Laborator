<?php
// File Upload · Scenario 11 — PUT Method Upload
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via HTTP PUT Method';
$scenarioNumber = 11;
$nextScenario = sprintf('../scenario%02d/', 12);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'The server accepts HTTP PUT method to upload files.',
    'PUT /uploads/shell.php can bypass multipart validation.',
    'This is HTTP Method Override.',
    'Goal: Use PUT to upload PHP shell.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Open Burp Suite, go to Repeater.',
    'Create new request: PUT /scenario11/uploads/shell.php HTTP/1.1',
    'Add Host header and Content-Length.',
    'Put PHP code in body: <?php echo \'pwned\'; ?>',
    'Send request. Server will save file via PUT method.',
    'Now GET /scenario11/uploads/shell.php to execute.',
    'Standard: PUT Method Bypass.',
];

$labRootCause = [
    'cwe' => 'CWE-434: PUT Method Upload',
    'owasp' => 'OWASP: HTTP Method Override',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed HTTP PUT method to upload files.</strong> PUT /uploads/shell.php can directly write file, bypassing POST validation.',
        '<strong>Mistake:</strong> Web server configured to allow PUT method. No authentication check for PUT. Attacker can PUT file directly without using upload form.',
        '<strong>Why it happens:</strong> Developer enabled WebDAV or PUT for testing and forgot to disable in production.',
        ],
        'code' => [
        '// VULNERABLE - Allows PUT method!',
        '# Apache config - allows PUT',
        '<Limit PUT>',
        '  Allow from all',
        '</Limit>',
        '',
        '<?php',
        '// No check for request method - accepts PUT!',
        '// Attacker sends:',
        '// PUT /uploads/shell.php HTTP/1.1',
        '// Host: victim.com',
        '// <?php system($_GET[\'cmd\']); ?>',
        '// Server saves file directly via PUT, bypassing upload form validation!',
        '?>',
        ],
        'impact' => 'Attacker uses PUT method to upload PHP shell directly to uploads folder, bypassing all POST validation. Gets RCE. PUT should be disabled.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Disable PUT, DELETE, and other dangerous methods. Only allow GET and POST. Check request method in code.',
        '<strong>Rule:</strong> Allow only needed HTTP methods.',
        ],
        'code' => [
        '// SECURE - Only allow GET and POST',
        '<?php',
        'if ($_SERVER[\'REQUEST_METHOD\'] != \'POST\' && $_SERVER[\'REQUEST_METHOD\'] != \'GET\') {',
        '  http_response_code(405);',
        '  die(\'Method not allowed\');',
        '}',
        '?>',
        '# Apache config secure:',
        '<LimitExcept GET POST>',
        '  Deny from all',
        '</LimitExcept>',
        ],
        'steps' => [
        'Disable PUT, DELETE, PATCH, OPTIONS methods if not needed',
        'Only allow GET and POST for upload',
        'Check $_SERVER[\'REQUEST_METHOD\'] in code',
        'Configure Apache/Nginx to block PUT',
        'Disable WebDAV if not used',
        'Use WAF to block dangerous methods',
        'Require authentication for file upload',
        ],
    ],
];

$link      = null;
$linkLabel = 'See the file';
$flash     = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

// the endpoint answers PUT directly: body = content, path or X-Filename = name
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'PUT') {
    $data = file_get_contents('php://input');
    $name = trim((string) ($_SERVER['HTTP_X_FILENAME'] ?? ''));

    if ($name === '') {
        $path = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?? '');
        $name = basename($path);
        if (stripos($path, 'uploads/') === false) {
            header('Content-Type: text/plain; charset=utf-8');
            http_response_code(400);
            echo "Upload failed. Put the filename under uploads/ or send X-Filename\n";
            exit;
        }
    } else {
        $name = basename($name);
    }

    if ($name === '' || $name === '.' || $name === '..' || !preg_match('/^[\w.\- ]+$/u', $name)) {
        header('Content-Type: text/plain; charset=utf-8');
        http_response_code(400);
        echo "Upload failed.\n";
        exit;
    }

    if ($data === false || $data === '') {
        header('Content-Type: text/plain; charset=utf-8');
        http_response_code(400);
        echo "Upload failed. The request body is empty.\n";
        exit;
    }

    if (file_put_contents($uploadsDir . '/' . $name, $data) === false) {
        header('Content-Type: text/plain; charset=utf-8');
        http_response_code(500);
        echo "Upload failed. The server could not save the file.\n";
        exit;
    }

    header('Content-Type: text/plain; charset=utf-8');
    echo 'Upload accepted: uploads/' . $name . ' (' . strlen((string) $data) . " bytes)\n";
    echo 'Open it at ' . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/uploads/' . rawurlencode($name) . "\n";
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    http_response_code(405);
    $flash = [
        'kind'  => 'fail',
        'title' => 'PUT required',
        'body'  => 'Intercept this request in Burp, change POST to PUT, and send the file as the raw request body.',
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<?php include __DIR__ . '/../menu/header.php'; ?>
<body>
<?php include __DIR__ . '/../menu/navbar.php'; ?>

    <main class="bench">
        <span class="num">File Upload · SCENARIO 11 · UPLOAD</span>
        <h1>HTTP PUT Method Upload</h1>
        <p>Bypass multipart checks by sending raw PUT request with Burp Repeater.</p>

        <div class="panel upload-form">
            <h2>Start the request</h2>
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
