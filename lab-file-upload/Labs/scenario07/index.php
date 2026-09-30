<?php
// File Upload · Scenario 07 — CSV Formula Injection
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'CSV Formula Injection via File Upload';
$scenarioNumber = 7;
$nextScenario = sprintf('../scenario%02d/', 8);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'The application accepts CSV uploads and does not sanitize formula characters (=, +, -, @).',
    'When opened in Excel/LibreOffice, formulas execute (DDE).',
    'Standard: CSV Injection / Formula Injection (OWASP). Goal: Upload CSV with =cmd|...',
];

$labHint = [
    'Create report.csv with content: =HYPERLINK("http://evil.com","Click") or =cmd|\' /C calc\'!A0',
    'For lab detection, use: =2+2 or =cmd|\'/C echo pwned\'!A0',
    'Upload report.csv via form. Use Burp Proxy to confirm upload.',
    'Download the stored CSV and open in spreadsheet - formula will execute.',
    'Lab will show Congratulations when formula payload is detected.',
    'PortSwigger style: Check stored file for formula execution.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) !== 'csv') {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Upload rejected', 'body' => 'Upload a CSV file.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the CSV.'];
    } else {
        $contents = (string) file_get_contents($uploadsDir . '/' . $safeName);
        $link = 'uploads/' . rawurlencode($safeName);
        if (preg_match('/(^|[,\r\n])[ \t]*["\']?[=+\-@]/', $contents)) {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 07.', 'body' => 'The CSV contains an unneutralized spreadsheet formula.'];
        } else {
            http_response_code(202);
            $flash = ['kind' => 'info', 'title' => 'CSV stored', 'body' => 'The CSV has no formula cell yet.'];
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
        <span class="num">File Upload · SCENARIO 07 · UPLOAD</span>
        <h1>CSV Formula Injection</h1>
        <p>CSV cells with =cmd|... execute when opened in Excel. Upload malicious CSV.</p>

        <div class="panel upload-form">
            <h2>Upload a CSV report</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a CSV:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".csv,text/csv" />
                <button class="primary-button" type="submit">Upload report</button>
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
