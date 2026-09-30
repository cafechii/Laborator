<?php
// File Upload · Scenario 25 — Archive Symlink Arbitrary File Read
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'File Read via Symlink in Archive Upload';
$scenarioNumber = 25;
$nextScenario = sprintf('../scenario%02d/', 26);
$uploadsDir = __DIR__ . '/uploads';
$extractRoot = $uploadsDir . '/extracted';
$secretFile = __DIR__ . '/secret.txt';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}
if (!is_dir($extractRoot)) {
    mkdir($extractRoot, 0775, true);
}
if (!is_file($secretFile)) {
    file_put_contents($secretFile, "FLAG{archive_symlink_extracted_successfully}\n");
}

$labDescription = [
    'Archive extractor keeps symbolic links (symlinks).',
    'Uploading symlink to /etc/passwd lets you read it via web.',
    'Server extracts tar/zip and keeps symlink file.',
    'This is Linux Only.',
    'Goal: Upload tar with symlink to secret file.',
];

$labHint = [
    'This lab works only on Linux.',
    'Create symlink archive with Python: import tarfile; tar=tarfile.open(\'symlink.tar\',\'w\'); info=tarfile.TarInfo(\'link\'); info.type=tarfile.SYMTYPE; info.linkname=\'../../secret.txt\'; tar.addfile(info); tar.close()',
    'Upload symlink.tar via form. Use Burp Proxy to intercept.',
    'Server extracts and keeps symlink.',
    'Then GET /scenario25/uploads/extracted/link - it will read secret.txt',
    'Check response for FLAG.',
    'Standard: Symlink Attack / Archive Symlink.',
];

$labRootCause = [
    'cwe' => 'CWE-59: Symlink Attack',
    'owasp' => 'OWASP: Archive Symlink',
    'bad' => [
        'explanation' => [
        '<strong>Programmer extracted archive and kept symbolic links.</strong> Attacker can create tar with symlink to /etc/passwd, and when server extracts, symlink points to /etc/passwd, then web can read it.',
        '<strong>Mistake:</strong> Used tar -xf without checking for symlinks. Extractor preserved symlink. Then file_get_contents on symlink reads target file.',
        '<strong>Why it happens:</strong> Developer did not know archive can contain symlinks. Linux Only.',
        ],
        'code' => [
        '// VULNERABLE - Preserves symlink!',
        '<?php',
        'shell_exec(\'tar -xf \' . escapeshellarg($_FILES[\'file\'][\'tmp_name\']) . \' -C uploads/\'); // Keeps symlink!',
        '// Attacker creates symlink.tar:',
        '// Python: import tarfile; tar=tarfile.open(\'symlink.tar\',\'w\'); info=tarfile.TarInfo(\'link\'); info.type=tarfile.SYMTYPE; info.linkname=\'../../secret.txt\'; tar.addfile(info); tar.close()',
        '// Archive contains symlink: link -> ../../secret.txt',
        '// Server extracts: uploads/link -> ../../secret.txt (symlink preserved!)',
        '// Attacker then GET /uploads/link and server reads ../../secret.txt via symlink!',
        ],
        'impact' => 'Attacker uploads tar with symlink to /etc/passwd or secret file, server extracts and keeps symlink, then attacker reads secret file via web. Symlink attack reads arbitrary files. Linux Only.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Don\'t preserve symlinks during extraction. Check file type before extraction, or reject symlinks. Extract to quarantine and check.',
        '<strong>Rule:</strong> Never preserve symlinks from user-controlled archives.',
        ],
        'code' => [
        '// SECURE - Reject symlinks',
        '<?php',
        '$phar = new PharData($_FILES[\'file\'][\'tmp_name\']);',
        'foreach ($phar as $file) {',
        '  if ($file->isLink()) { die(\'Symlink not allowed\'); }',
        '}',
        '$extractDir = \'uploads/extracted/\';',
        'shell_exec(\'tar -xf \' . escapeshellarg($_FILES[\'file\'][\'tmp_name\']) . \' -C \' . escapeshellarg($extractDir));',
        '$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($extractDir));',
        'foreach ($files as $f) {',
        '  if (is_link($f->getPathname())) {',
        '    unlink($f->getPathname());',
        '    die(\'Symlink found and removed\');',
        '  }',
        '}',
        '?>',
        ],
        'steps' => [
        'Reject archives containing symlinks',
        'Check each file in archive if it is symlink before extraction',
        'Use PharData to check isLink()',
        'Extract with --no-same-owner flag',
        'After extraction, scan for symlinks with is_link() and remove',
        'Extract to quarantine folder not web accessible',
        'Don\'t follow symlinks when reading files - use realpath() and check if inside allowed dir',
        'Use open_basedir to restrict file access',
        ],
    ],
];

$link = null;
$linkLabel = 'Open the extracted symlink';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

    if (!in_array($ext, ['tar', 'zip'], true)) {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Unsupported archive', 'body' => 'Upload a .tar or .zip archive.'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The archive was not received properly.'];
    } else {
        $destArchive = $uploadsDir . '/' . $safeName;
        if (!move_uploaded_file($file['tmp_name'], $destArchive)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the archive.'];
        } else {
            // Extract the archive into $extractRoot
            if ($ext === 'tar') {
                @shell_exec('tar -xf ' . escapeshellarg($destArchive) . ' -C ' . escapeshellarg($extractRoot) . ' 2>&1');
            } else {
                @shell_exec('unzip -q -o ' . escapeshellarg($destArchive) . ' -d ' . escapeshellarg($extractRoot) . ' 2>&1');
            }

            // Inspect extracted files for symlinks
            $foundSymlink = false;
            $symlinkTarget = '';
            $readContent = '';
            $linkPath = '';

            $items = @scandir($extractRoot) ?: [];
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') {
                    continue;
                }
                $path = $extractRoot . '/' . $item;
                if (is_link($path)) {
                    $foundSymlink = true;
                    $symlinkTarget = (string) @readlink($path);
                    $readContent = (string) @file_get_contents($path);
                    $linkPath = 'uploads/extracted/' . rawurlencode($item);
                    break;
                }
            }

            if ($foundSymlink && $readContent !== '') {
                $extraOutput = "Symlink target: " . $symlinkTarget . "\n\nResolved content:\n" . $readContent;
                $link = $linkPath;
                $flash = [
                    'kind' => 'ok',
                    'title' => 'Congratulations! You solved Scenario 25.',
                    'body' => 'The server preserved the symlink and exposed the target file: ' . htmlspecialchars($symlinkTarget, ENT_QUOTES),
                ];
            } elseif ($foundSymlink) {
                $extraOutput = "Symlink target: " . $symlinkTarget . " (target could not be read or was empty)";
                $link = $linkPath;
                $flash = [
                    'kind' => 'fail',
                    'title' => 'Symlink found but unreadable',
                    'body' => 'Make sure the symlink points to ../../secret.txt or /etc/hostname.',
                ];
            } else {
                http_response_code(422);
                $flash = [
                    'kind' => 'fail',
                    'title' => 'No symlink detected',
                    'body' => 'The archive did not contain any symbolic links. Use ln -s and tar -cf (or zip -y).',
                ];
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
        <span class="num">File Upload · SCENARIO 25 · UPLOAD</span>
        <h1>Symlink Attack in Archive</h1>
        <p>Archive with symlink to /etc/passwd. Create tar with symlink via Python and upload.</p>

        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Linux Only</strong>
        </div>

        <div class="panel upload-form">
            <h2>Upload an archive (TAR or ZIP)</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select an archive (.tar or .zip):</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".tar,.zip,application/x-tar,application/zip" />
                <button class="primary-button" type="submit">Extract archive</button>
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
