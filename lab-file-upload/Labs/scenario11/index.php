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
    'The server accepts HTTP PUT requests to upload files directly, bypassing multipart validation.',
    'PUT /uploads/shell.php with raw PHP body writes file.',
    'Standard: HTTP PUT Bypass / Unrestricted PUT. Goal: Use Burp to send PUT.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'In Burp Suite, intercept a normal POST upload request.',
    'Send to Repeater (Ctrl+R).',
    'Change method from POST to PUT. Change path to /scenario11/uploads/shell.php',
    'Remove multipart headers. Set Content-Type: application/octet-stream or text/plain.',
    'Add header X-Filename: shell.php (lab checks this) or use URL path.',
    'Body: <?php echo \'pwned\'; ?> raw PHP, NOT multipart.',
    'Send PUT request. Should get 200 Congratulations. Then GET /scenario11/uploads/shell.php',
    'PortSwigger: \'Web shell upload via PUT\'.',
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
