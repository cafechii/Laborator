<?php
// File Upload · Scenario 13 — SVG External Entity File Read
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'XXE via SVG File Upload';
$scenarioNumber = 13;
$nextScenario = sprintf('../scenario%02d/', 14);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'SVG parser may resolve XML external entities (XXE). An entity can read local files: <!ENTITY xxe SYSTEM \'file:///etc/hostname\'>',
    'Standard: XXE via SVG / XML Upload. Goal: Read /etc/hostname or /etc/passwd.',
];

$labHint = [
    'Create svg with XXE payload: <?xml version=\'1.0\'?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \'file:///etc/hostname\'>]><svg><text>&xxe;</text></svg>',
    'In Burp Suite, upload the file. Intercept POST to ensure it\'s sent as SVG.',
    'Send to Repeater if needed. The server parses SVG and expands entity.',
    'Response or stored file content will contain /etc/hostname.',
    'For SSRF XXE: <!ENTITY xxe SYSTEM \'http://127.0.0.1:8080/scenario15/?internal=1\'>',
    'PortSwigger: \'XXE via SVG\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    $contents = (string) @file_get_contents($file['tmp_name']);
    $expandedText = null;
    if (class_exists('DOMDocument')) {
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        if (@$dom->loadXML($contents, LIBXML_NOENT | LIBXML_DTDLOAD)) {
            $txt = trim($dom->textContent);
            if ($txt !== '') {
                $expandedText = $txt;
            }
        }
        libxml_clear_errors();
    }
    if ($expandedText === null && preg_match('/<!ENTITY\s+([A-Za-z_][\w.-]*)\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $contents, $entity)) {
        $val = @file_get_contents($entity[2]);
        if ($val !== false && trim((string) $val) !== '') {
            $expandedText = (string) $val;
        }
    }

    if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) !== 'svg') {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Upload rejected', 'body' => 'Upload an SVG document.'];
    } elseif ($expandedText === null) {
        http_response_code(422);
        $flash = ['kind' => 'fail', 'title' => 'No external entity resolved', 'body' => 'The SVG does not define or expand a readable SYSTEM entity.'];
    } else {
        move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName);
        $link = 'uploads/' . rawurlencode($safeName);
        $extraOutput = $expandedText;
        $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 13.', 'body' => 'The SVG parser expanded the external entity successfully.'];
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
        <span class="num">File Upload · SCENARIO 13 · UPLOAD</span>
        <h1>XXE via SVG Upload</h1>
        <p>SVG XML parser resolves external entities. Upload XXE payload to read /etc/hostname.</p>

        <div class="panel upload-form">
            <h2>Upload an SVG document</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select an SVG:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit">Upload</button>
            </form>
        </div>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($extraOutput !== null): ?>
            <pre class="panel hint-code" aria-label="Parser output"><?= htmlspecialchars($extraOutput, ENT_QUOTES) ?></pre>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">Next scenario &rarr;</a>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
