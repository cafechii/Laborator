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
    'The app accepts CSV files and does not filter formula characters.',
    'Characters like = + - @ can execute as formula in Excel.',
    'When victim opens CSV in Excel, formula runs.',
    'Standard: CSV Injection / Formula Injection.',
    'Goal: Upload CSV with malicious formula.',
];

$labHint = [
    'Create file report.csv with content: =2+2 or =HYPERLINK("http://evil.com","Click")',
    'For RCE test, use: =cmd|\' /C calc\'!A0 or =cmd|\'/C echo pwned\'!A0',
    'Upload report.csv via form. Use Burp Proxy to check upload.',
    'Download the saved file and open in Excel - formula will execute.',
    'Lab will show Congratulations when it detects formula.',
    'Standard name: CSV Injection.',
];

$labRootCause = [
    'cwe' => 'CWE-1236: CSV Injection',
    'owasp' => 'OWASP: Formula Injection',
    'bad' => [
        'explanation' => [
        '<strong>Programmer accepted CSV uploads and did not sanitize formula characters.</strong> Characters like =, +, -, @ at start of cell are treated as formula by Excel.',
        '<strong>Mistake:</strong> Saved CSV content directly without filtering. When user opens CSV in Excel, formula executes.',
        '<strong>Why it happens:</strong> Developer did not know Excel treats = as formula start. Thought CSV is just text.',
        ],
        'code' => [
        '// VULNERABLE - No CSV sanitization!',
        '<?php',
        '$content = file_get_contents($_FILES[\'file\'][\'tmp_name\']);',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '?>',
        '// Attacker uploads report.csv with:',
        '// =HYPERLINK("http://evil.com","Click here")',
        '// =cmd|\'/C calc\'!A0  - runs calc.exe on Windows',
        '// When victim opens CSV in Excel, formula runs!',
        ],
        'impact' => 'Attacker uploads CSV with malicious formula. When victim opens in Excel, formula executes, can exfiltrate data, run commands, or phish.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Sanitize CSV cells that start with =, +, -, @, tab, carriage return. Add single quote or space at start, or reject.',
        '<strong>Rule:</strong> Treat CSV as code, not just text. Excel formulas are dangerous.',
        ],
        'code' => [
        '// SECURE - Sanitize CSV formulas',
        '<?php',
        '$content = file_get_contents($_FILES[\'file\'][\'tmp_name\']);',
        '$lines = explode("\\n", $content);',
        'foreach ($lines as $line) {',
        '  $cells = str_getcsv($line);',
        '  foreach ($cells as $cell) {',
        '    if (preg_match(\'/^[=\\+\\-@\\t\\r]/\', $cell)) {',
        '      $cell = "\'" . $cell; // Add single quote to prevent formula',
        '    }',
        '  }',
        '}',
        '?>',
        ],
        'steps' => [
        'Sanitize cells starting with = + - @',
        'Add single quote \' at beginning to neutralize formula',
        'Use CSV library that handles formula escaping',
        'Validate CSV structure',
        'Warn users to not enable macros when opening CSV',
        'Consider using other format like JSON instead of CSV',
        ],
    ],
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
