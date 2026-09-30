<?php
// File Upload · Scenario 27 — uWSGI Configuration Upload - FIXED for Windows + correct payload
// Now accepts both @(exec://id) and [uwsgi] exec = id

$pageTitle = 'RCE via uWSGI Configuration File Upload';
$scenarioNumber = 27;
$nextScenario = sprintf('../scenario%02d/', 28);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'uWSGI allows exec:// scheme in config files.',
    'Uploading malicious uwsgi.ini with exec:// leads to RCE.',
    'Server parses ini file and executes command in exec://.',
    'This is Linux Only.',
    'Goal: Upload uwsgi.ini with exec payload.',
];

$labHint = [
    'This lab works only on Linux.',
    'Create file uwsgi.ini with content: @(exec://id) or [uwsgi] exec = id',
    'Payload examples: @(exec://id) , @(exec://cat /etc/passwd) , exec = id',
    'Save file with .ini extension: uwsgi.ini',
    'Upload via form. Use Burp Proxy to intercept.',
    'Server does shell_exec(id) and returns uid.',
    'Simplest test: @(exec://echo UWSGI_OK)',
    'Standard: uWSGI Config RCE.',
];

$labRootCause = [
    'cwe' => 'CWE-78: uWSGI Config RCE',
    'owasp' => 'OWASP: Config Injection',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed .ini upload and uWSGI server parses .ini with exec:// scheme which executes command.</strong> uWSGI config can have @(exec://id) which runs id command.',
        '<strong>Mistake:</strong> Allowed .ini upload and uWSGI loads all .ini files from directory. No check for exec:// or dangerous directives in ini content.',
        '<strong>Why it happens:</strong> Developer did not know uWSGI ini can execute commands via exec://. Thought ini is just config, not code. Linux Only.',
        ],
        'code' => [
        '// VULNERABLE - uWSGI exec:// RCE!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // uwsgi.ini',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $filename);',
        '// uWSGI server loads all .ini files in directory and parses exec://',
        '// Attacker uploads uwsgi.ini with:',
        '// [uwsgi]',
        '// exec = id',
        '// Or: @(exec://id)',
        '// uWSGI parses and runs shell_exec(id)! RCE!',
        '?>',
        ],
        'impact' => 'Attacker uploads malicious uwsgi.ini with exec:// payload and gets RCE when uWSGI reloads config. Config file injection leads to RCE. Linux Only.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block .ini and other config files. Don\'t allow config upload. If ini needed, parse manually and reject exec, exec://, and other dangerous directives. Store uploads outside config directory.',
        '<strong>Rule:</strong> Never allow config files upload in config directory.',
        ],
        'code' => [
        '// SECURE - Block .ini and check content',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));',
        'if ($ext == \'ini\' || $ext == \'conf\' || $ext == \'config\') { die(\'Config files not allowed\'); }',
        '$content = file_get_contents($_FILES[\'file\'][\'tmp_name\']);',
        'if (stripos($content, \'exec://\') !== false || stripos($content, \'exec =\') !== false) {',
        '  die(\'Dangerous directive found\');',
        '}',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        ],
        'steps' => [
        'Block .ini, .conf, .config, .yaml, .xml config files',
        'Check file content for exec://, exec =, and other dangerous patterns',
        'Store uploads outside uWSGI config directory',
        'Disable exec plugin in uWSGI if not needed',
        'Use allowlist for extensions',
        'Randomize filename',
        'Set proper permissions - uploads should not be readable as config by uWSGI',
        ],
    ],
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null;

$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    $contents = (string) @file_get_contents($file['tmp_name']);
    
    if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) !== 'ini') {
        http_response_code(415);
        $flash = ['kind' => 'fail', 'title' => 'Upload rejected', 'body' => 'Upload a .ini configuration file. Example: uwsgi.ini'];
    } elseif ($file['error'] !== UPLOAD_ERR_OK || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the configuration.'];
    } else {
        $command = null;
        // Try multiple patterns for flexibility
        if (preg_match('/@\(exec:\/\/([^\)\r\n]+)\)/i', $contents, $m)) {
            $command = trim($m[1]);
        } elseif (preg_match('/exec:\/\/([^\r\n]+)/i', $contents, $m)) {
            $command = trim($m[1]);
        } elseif (preg_match('/exec\s*=\s*([^\r\n]+)/i', $contents, $m)) {
            $command = trim($m[1]);
        }
        
        if ($command === null) {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'No exec scheme', 'body' => 'The configuration has no exec directive. Use: @(exec://id) or [uwsgi] exec = id'];
        } else {
            // Clean command from quotes
            $command = trim($command, " \t\"'");
            $extraOutput = (string) @shell_exec($command . ' 2>&1');
            // Also try without 2>&1 for Windows
            if (trim($extraOutput) === '') {
                $extraOutput = (string) @shell_exec($command);
            }
            
            if (strpos($extraOutput, 'UWSGI_OK') !== false || trim($extraOutput) !== '' || preg_match('/uid=|www-data|root|\\\\user|Volume|whoami/i', $extraOutput)) {
                // If output empty but command was executed (e.g., touch), still consider success if command contains known payload
                if (trim($extraOutput) === '' && preg_match('/^(id|whoami|echo|dir|ls)/i', $command)) {
                    $extraOutput = "Command executed: $command\nOutput empty but command ran. Try: echo UWSGI_OK\n";
                }
                $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 27.', 'body' => 'The configuration parser evaluated exec: ' . $command];
            } else {
                http_response_code(422);
                $flash = ['kind' => 'fail', 'title' => 'Command produced no output', 'body' => 'The exec directive executed but produced no output. Use: @(exec://echo UWSGI_OK) or @(exec://id). Command tried: ' . $command];
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
        <span class="num">File Upload · SCENARIO 27 · UPLOAD</span>
        <h1>uWSGI Config RCE</h1>
        <p>uWSGI exec:// scheme in ini leads to RCE. Upload malicious uwsgi.ini. Works on Windows & Linux.</p>
        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Linux Only</strong>
        </div>

        <div class="panel" style="background:rgba(60,255,60,0.1); border:1px solid #3c3; border-radius:8px; padding:10px; margin-bottom:16px; font-size:13px;">
            <strong>✅ Windows & Linux - Payloads:</strong><br>
            <code>@(exec://id)</code> or <code>@(exec://whoami)</code> or <code>@(exec://echo UWSGI_OK)</code><br>
            or INI: <code>[uwsgi]<br>exec = id</code> (Linux) / <code>exec = whoami</code> (Windows)
        </div>

        <div class="panel upload-form">
            <h2>Upload a uWSGI configuration</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select uwsgi.ini:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".ini,text/plain" />
                <button class="primary-button" type="submit">Load configuration</button>
            </form>
            <div style="margin-top:12px; font-size:12px; background:#1a1a2e; padding:8px; border-radius:4px;">
                <strong>نمونه فایل uwsgi.ini:</strong><br>
                <code>@(exec://echo UWSGI_OK)</code> ← ساده ترین<br>
                یا<br>
                <code>[uwsgi]<br>exec = echo UWSGI_OK</code>
            </div>
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
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
