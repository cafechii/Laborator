<?php
// File Upload · Scenario 26 — Image Processor Command Injection - FIXED for Windows + Linux
// Now works on both Windows and Linux

$pageTitle = 'RCE via ImageMagick Command Injection (ImageTragick)';
$scenarioNumber = 26;
$nextScenario = sprintf('../scenario%02d/', 27);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'ImageMagick processes image and uses filename in shell command without escape.',
    'You can inject shell command via filename like test.jpg|id',
    'This is ImageTragick CVE-2016-3714.',
    'Goal: Inject command via filename to get RCE.',
];

$labHint = [
    '===== Linux (ImageMagick) =====',
    'Open Burp Suite, intercept image upload POST /scenario26/, send to Repeater (Ctrl+R).',
    'In Repeater, find filename="test.jpg"',
    'Change to: filename="test.jpg|id" or filename="test.jpg|echo IMAGE_PROCESSOR_OK"',
    'Note: Use | not ; because ; may be stripped. Linux payloads: |id , |whoami , `id` , $(id)',
    'Click Send. Server runs identify uploads/test.jpg|id - part after | executes.',
    'You should see uid=1000 or IMAGE_PROCESSOR_OK in response.',
    '',
    '===== Windows (ImageMagick) =====',
    'For Windows, use: filename="test.jpg & whoami" or filename="test.jpg & echo IMAGE_PROCESSOR_OK" with space before &.',
    'Windows payloads: & whoami , | whoami. Use whoami not id on Windows.',
    'Click Send. Server runs identify ... & whoami - whoami executes.',
    'You should see desktop\\user or IMAGE_PROCESSOR_OK.',
    'Standard: ImageMagick Command Injection / ImageTragick (CVE-2016-3714).',
];

$labRootCause = [
    'cwe' => 'CWE-78: Command Injection via Filename',
    'owasp' => 'OWASP: ImageTragick CVE-2016-3714',
    'bad' => [
        'explanation' => [
        '<strong>Programmer used filename in shell command without escaping.</strong> ImageMagick command like identify uploads/test.jpg was built with user filename, and filename contained |id which executes command.',
        '<strong>Mistake:</strong> Used shell_exec("identify uploads/" . $filename) without escapeshellarg(). Attacker sets filename to test.jpg|id and shell runs identify uploads/test.jpg|id - part after | is executed as new command.',
        '<strong>Why it happens:</strong> Developer did not know filename is user input and must be escaped when used in shell command.',
        ],
        'code' => [
        '// VULNERABLE - Command injection via filename!',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\']; // test.jpg|id',
        '$dest = \'uploads/\' . $filename;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], $dest);',
        '$output = shell_exec(\'identify \' . $dest); // identify uploads/test.jpg|id',
        '// Shell sees: identify uploads/test.jpg | id',
        '// | is pipe, so runs identify uploads/test.jpg and then runs id command!',
        'echo $output; // Shows id output: uid=0(root)!',
        '?>',
        ],
        'impact' => 'Attacker injects shell command via filename like test.jpg|id and gets RCE. ImageMagick command injection is critical (ImageTragick CVE-2016-3714).',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Never use user input in shell command without escaping. Use escapeshellarg() for arguments and escapeshellcmd() for command. Better, avoid shell commands completely, use PHP library.',
        '<strong>Rule:</strong> Escape shell arguments or avoid shell.',
        ],
        'code' => [
        '// SECURE - Escape shell arg or avoid shell',
        '<?php',
        '$filename = $_FILES[\'file\'][\'name\'];',
        '$safeName = basename($filename);',
        '$ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        '$dest = \'uploads/\' . $newName;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], $dest);',
        '$output = shell_exec(\'identify \' . escapeshellarg($dest)); // Safe!',
        '// Better: avoid shell, use PHP Imagick library',
        '// $imagick = new Imagick($dest);',
        '?>',
        ],
        'steps' => [
        'Never use user input directly in shell command',
        'Use escapeshellarg() to escape filename argument',
        'Use escapeshellcmd() to escape entire command',
        'Better: avoid shell commands, use PHP library like Imagick PHP extension, GD',
        'Validate filename - only allow alphanumeric, dot, dash, underscore',
        'Reject filenames containing | ; & ` $ ( ) < >',
        'Randomize filename - attacker cannot control name used in shell',
        'Use whitelist for allowed characters in filename',
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
    $destPath = $uploadsDir . '/' . $safeName;
    
    if ($file['error'] !== UPLOAD_ERR_OK || !move_uploaded_file($file['tmp_name'], $destPath)) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed', 'body' => 'The server could not save the image.'];
    } else {
        // Simulate ImageMagick command with injection vulnerability
        // Vulnerable: $command = 'identify ' . $destPath . ' 2>&1';
        $command = 'identify ' . $destPath . ' 2>&1';
        $output = (string) @shell_exec($command);
        
        // For Windows compatibility, also try to detect injection in filename and simulate
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $hasInjection = false;
        $injectedOutput = '';
        
        // Check if filename contains shell injection characters
        if (preg_match('/[;|&`$]/', $safeName)) {
            $hasInjection = true;
            // Extract potential command after injection char
            // Look for patterns like ;id, |id, & whoami, ;echo, etc
            if (preg_match('/[;|&]\s*(.+)$/', $safeName, $m)) {
                $injectedCmd = trim($m[1], ' "');
                // Clean up trailing chars like .jpg
                $injectedCmd = preg_replace('/\.(jpg|png|gif|jpeg).*$/i', '', $injectedCmd);
                $injectedCmd = trim($injectedCmd);
                
                // Simulate execution for common payloads
                if (stripos($injectedCmd, 'IMAGE_PROCESSOR_OK') !== false) {
                    $injectedOutput = "IMAGE_PROCESSOR_OK\n";
                } elseif (preg_match('/\b(id|whoami|dir|ls)\b/i', $injectedCmd, $cmdMatch)) {
                    $cmd = strtolower($cmdMatch[1]);
                    if ($cmd === 'id') {
                        $injectedOutput = "uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)\n";
                    } elseif ($cmd === 'whoami') {
                        if ($isWindows) {
                            $injectedOutput = "desktop-abc\\user\n";
                        } else {
                            $injectedOutput = "www-data\n";
                        }
                    } elseif ($cmd === 'dir' && $isWindows) {
                        $injectedOutput = " Volume in drive C is Windows\n Directory of C:\\xampp\\htdocs\n";
                    } elseif ($cmd === 'ls') {
                        $injectedOutput = "index.php\nuploads\n";
                    }
                    // Try real execution too
                    $realOut = @shell_exec($injectedCmd . ' 2>&1');
                    if ($realOut) $injectedOutput .= $realOut;
                } else {
                    // Try to execute the injected command for real
                    $realOut = @shell_exec($injectedCmd . ' 2>&1');
                    if ($realOut) {
                        $injectedOutput = $realOut;
                    } else {
                        $injectedOutput = "Command executed: $injectedCmd\nIMAGE_PROCESSOR_OK (simulated)\n";
                    }
                }
            }
        }
        
        $combinedOutput = $output . "\n" . $injectedOutput;
        $extraOutput = "Command: $command\nOS: " . PHP_OS . "\nOutput:\n" . $combinedOutput;
        
        // Check for success - works on both Windows and Linux
        $success = false;
        if (strpos($combinedOutput, 'IMAGE_PROCESSOR_OK') !== false) $success = true;
        if (is_file('/tmp/scenario26-proof')) $success = true;
        if (preg_match('/uid=\d+/i', $combinedOutput)) $success = true;
        if (preg_match('/www-data|root|desktop|\\\\user|Volume in drive/i', $combinedOutput)) $success = true;
        if ($hasInjection && $injectedOutput !== '') $success = true;
        // If filename contains injection chars, consider it attempt
        if (preg_match('/[;|&`]/', $safeName) && (stripos($safeName, 'echo') !== false || stripos($safeName, 'id') !== false || stripos($safeName, 'whoami') !== false)) {
            $success = true;
            if (strpos($extraOutput, 'IMAGE_PROCESSOR_OK') === false) {
                $extraOutput .= "\n[Windows/Linux] Injection detected in filename: $safeName\n";
            }
        }

        if ($success) {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 26.',
                      'body'  => 'The image processor command was injected through the filename. OS: ' . PHP_OS . ' - Injection: ' . $safeName];
        } else {
            http_response_code(422);
            $flash = ['kind' => 'fail', 'title' => 'No command injection',
                      'body'  => 'The image was processed, but the command was not injected. Intercept in Burp and try: Linux: ";echo IMAGE_PROCESSOR_OK" or Windows: "& echo IMAGE_PROCESSOR_OK" in filename. Current OS: ' . PHP_OS];
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
        <span class="num">File Upload · SCENARIO 26 · UPLOAD</span>
        <h1>ImageMagick Command Injection</h1>
        <p>ImageMagick uses filename in shell command. Inject via filename using Burp Repeater. Works on Windows & Linux.</p>

        <div class="panel" style="background:rgba(60,255,60,0.1); border:1px solid #3c3; border-radius:8px; padding:10px; margin-bottom:16px; font-size:13px;">
            <strong>✅ Windows & Linux Compatible</strong><br>
            Linux payload: <code>test.jpg;echo IMAGE_PROCESSOR_OK</code> or <code>test.jpg;id</code><br>
            Windows payload: <code>test.jpg & echo IMAGE_PROCESSOR_OK</code> or <code>test.jpg & whoami</code><br>
            OS detected: <strong><?= htmlspecialchars(PHP_OS, ENT_QUOTES) ?></strong>
        </div>

        <div class="panel upload-form">
            <h2>Process an image</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select an image:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit">Process image</button>
            </form>
        </div>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($extraOutput !== null): ?>
            <pre class="panel hint-code" aria-label="Parser output" style="white-space:pre-wrap; font-size:12px;"><?= htmlspecialchars($extraOutput, ENT_QUOTES) ?></pre>
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
