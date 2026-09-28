<?php
// File Upload · Scenario 16 — Document Parser XXE
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'XXE via Office Document Upload (OOXML)';
$scenarioNumber = 16;
$nextScenario = sprintf('../scenario%02d/', 17);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'Office documents (.docx, .xlsx) are ZIP archives containing XML. Parser may resolve XXE in [Content_Types].xml or document.xml.',
    'Standard: XXE in OOXML / Document XXE. Goal: Read /etc/hostname via docx.',
];

$labHint = [
    'Create a .docx file (it\'s a ZIP). Unzip it: unzip report.docx -d docx/',
    'Edit [Content_Types].xml or word/document.xml and add <!DOCTYPE foo [<!ENTITY xxe SYSTEM \'file:///etc/hostname\'>]> and reference &xxe;',
    'Re-zip: cd docx && zip -r ../xxe.docx *',
    'Upload xxe.docx via form. Use Burp Proxy to intercept.',
    'Server parses XML and expands entity, showing /etc/hostname in response.',
    'PortSwigger: \'XXE via file upload\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    $contents = (string) @file_get_contents($file['tmp_name']);
    $hasEntity = preg_match('/<!ENTITY\b/i', $contents);
    if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) !== 'xml') {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Upload rejected', 'body' => 'Upload an XML document (.xml).'];
    } elseif (!$hasEntity) {
        http_response_code(422);
        $flash = ['kind' => 'fail', 'title' => 'No entity definition', 'body' => 'The XML document does not define any external entities (DTD/ENTITY).'];
    } elseif (!class_exists('DOMDocument')) {
        http_response_code(500);
        $flash = ['kind' => 'fail', 'title' => 'XML support unavailable', 'body' => 'DOMDocument extension is required.'];
    } else {
        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $loaded = @$dom->loadXML($contents, LIBXML_NOENT | LIBXML_DTDLOAD);
        libxml_clear_errors();
        move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName);
        $link = 'uploads/' . rawurlencode($safeName);
        if ($loaded && trim($dom->textContent) !== '') {
            $extraOutput = trim($dom->textContent);
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 16.', 'body' => 'The document parser expanded the external entity.'];
        } else {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'Entity not expanded', 'body' => 'The XML could not be parsed or produced no content.'];
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
        <span class="num">File Upload · SCENARIO 16 · UPLOAD</span>
        <h1>XXE via Document Upload</h1>
        <p>Office docs are ZIP with XML. Inject XXE entity to read local files.</p>

        <div class="panel upload-form">
            <h2>Upload a document</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select XML:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".xml,application/xml" />
                <button class="primary-button" type="submit">Parse document</button>
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
