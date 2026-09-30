<?php
// File Upload · Scenario 14 — ZIP Decompression Bomb
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'DoS via Zip Bomb (Decompression Bomb)';
$scenarioNumber = 14;
$nextScenario = sprintf('../scenario%02d/', 15);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'Server checks compressed ZIP size but not uncompressed size.',
    'A small ZIP can expand to huge size (Zip Bomb).',
    'This can cause disk full or DoS.',
    'Standard: Zip Bomb / Decompression Bomb.',
    'Goal: Upload small ZIP that expands to big file.',
];

$labHint = [
    'Create a ZIP bomb: many files with same content or highly compressible zeros.',
    'For example, create file with 1GB of zeros, compress it (will be small).',
    'Upload ZIP via form. Use Burp Proxy to see request.',
    'Server extracts and disk fills, or shows Congratulations when detects bomb.',
    'Standard: Zip Bomb.',
];

$labRootCause = [
    'cwe' => 'CWE-409: Zip Bomb',
    'owasp' => 'OWASP: Decompression Bomb',
    'bad' => [
        'explanation' => [
        '<strong>Programmer checked compressed ZIP size but not uncompressed size.</strong> Small ZIP can expand to huge size (like 42.zip - 42KB expands to 4.5PB).',
        '<strong>Mistake:</strong> Checked $_FILES[\'file\'][\'size\'] (compressed size) but not total size after extraction. No limit on number of files or uncompressed size.',
        '<strong>Why it happens:</strong> Developer did not know about Zip Bomb attack. Thought small ZIP is safe.',
        ],
        'code' => [
        '// VULNERABLE - Only checks compressed size!',
        '<?php',
        'if ($_FILES[\'file\'][\'size\'] > 1024*1024) { // Checks compressed size only - 1MB',
        '  die(\'File too big\');',
        '}',
        '$zip = new ZipArchive();',
        '$zip->open($_FILES[\'file\'][\'tmp_name\']);',
        '$zip->extractTo(\'uploads/\'); // Extracts without checking uncompressed size!',
        '// Attacker uploads 42.zip - 42KB compressed, but 4.5PB uncompressed!',
        '// Server extracts and disk becomes full! DoS!',
        '?>',
        ],
        'impact' => 'Attacker uploads small ZIP that expands to huge size, filling disk or memory. Causes Denial of Service (DoS). Server crashes or becomes slow.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Check uncompressed size before extraction. Limit total uncompressed size, number of files, and compression ratio.',
        '<strong>Rule:</strong> Always check uncompressed size, not just compressed.',
        ],
        'code' => [
        '// SECURE - Check uncompressed size',
        '<?php',
        '$zip = new ZipArchive();',
        '$zip->open($_FILES[\'file\'][\'tmp_name\']);',
        '$totalUncompressed = 0;',
        '$fileCount = 0;',
        'for ($i=0; $i<$zip->numFiles; $i++) {',
        '  $stat = $zip->statIndex($i);',
        '  $totalUncompressed += $stat[\'size\'];',
        '  $fileCount++;',
        '  if ($totalUncompressed > 10*1024*1024) { die(\'Uncompressed too big\'); }',
        '  if ($fileCount > 100) { die(\'Too many files\'); }',
        '}',
        '$zip->extractTo(\'uploads/\');',
        '?>',
        ],
        'steps' => [
        'Check uncompressed size for each file in ZIP',
        'Limit total uncompressed size (e.g., 10MB)',
        'Limit number of files in ZIP (e.g., 100)',
        'Check compression ratio - if >100x, likely bomb',
        'Use streaming extraction with limits',
        'Set disk quota for upload folder',
        'Use antivirus to scan ZIP',
        'Consider not allowing ZIP upload if not needed',
        ],
    ],
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    if (!class_exists('ZipArchive')) {
        http_response_code(500);
        $flash = ['kind' => 'fail', 'title' => 'ZIP support unavailable', 'body' => 'Use the Dockerfile for this lab.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The archive was not received.'];
    } else {
        $zip = new ZipArchive();
        if ($zip->open($file['tmp_name']) !== true) {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'Invalid archive', 'body' => 'The file is not a readable ZIP archive.'];
        } else {
            $expanded = 0;
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $expanded += (int) ($stat['size'] ?? 0);
            }
            $compressed = filesize($file['tmp_name']);
            $zip->close();
            if ($compressed < 200000 && $expanded > 8000000) {
                $extraOutput = 'compressed bytes: ' . $compressed . "\nuncompressed bytes: " . $expanded;
                $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 14.', 'body' => 'The server accepted a small archive with a dangerous expansion ratio.'];
            } else {
                http_response_code(422);
                $flash = ['kind' => 'fail', 'title' => 'Archive is not oversized enough', 'body' => 'Use a small, highly compressible archive with more than 8 MB of uncompressed data.'];
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
        <span class="num">File Upload · SCENARIO 14 · UPLOAD</span>
        <h1>Zip Bomb (Decompression Bomb)</h1>
        <p>Small ZIP expands to huge size causing DoS. Upload highly compressible ZIP.</p>

        <div class="panel upload-form">
            <h2>Upload a compressed archive</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a ZIP:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".zip,application/zip" />
                <button class="primary-button" type="submit">Check archive</button>
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
