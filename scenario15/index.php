<?php
// File Upload · Scenario 15 — SSRF via Remote URL Upload
// UI: has both file upload (like other labs) + URL fetcher below it
// File upload returns 200 but does NOT solve, SSRF via URL solves

$pageTitle = 'SSRF via Remote URL File Upload';
$scenarioNumber = 15;
$nextScenario = sprintf('../scenario%02d/', 16);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'This lab lets you provide URL. Server downloads file from URL and saves it.',
    'Server does not block internal URLs like 127.0.0.1.',
    'This is SSRF via file upload.',
    'Goal: Provide internal URL to read internal service.',
];

$labHint = [
    'Look for URL input field in lab.',
    'Enter URL like http://127.0.0.1:80/ or http://localhost/ or http://169.254.169.254/',
    'Server will fetch URL and save content.',
    'Use Burp Repeater to send URL parameter.',
    'Check uploaded file link - it contains internal service response.',
    'Standard: SSRF via URL Upload.',
];

$labRootCause = [
    'cwe' => 'CWE-918: SSRF via URL Upload',
    'owasp' => 'OWASP: Server-Side Request Forgery',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed user to provide URL, server fetches URL and saves file.</strong> No check if URL is internal like http://127.0.0.1 or http://169.254.169.254 (AWS metadata).',
        '<strong>Mistake:</strong> Used file_get_contents($_POST[\'url\']) or curl without blocking internal IPs. Attacker can make server request internal services.',
        '<strong>Why it happens:</strong> Developer wanted to allow URL upload for convenience, but forgot SSRF risk.',
        ],
        'code' => [
        '// VULNERABLE - SSRF via URL upload!',
        '<?php',
        '$url = $_POST[\'url\']; // User controls URL!',
        '$content = file_get_contents($url); // Server fetches URL - SSRF!',
        'file_put_contents(\'uploads/\' . basename($url), $content);',
        '?>',
        '// Attacker provides URL: http://127.0.0.1:80/admin',
        '// Server fetches http://127.0.0.1:80/admin - internal service! SSRF!',
        '// Or: http://169.254.169.254/latest/meta-data/ - AWS metadata!',
        ],
        'impact' => 'Attacker makes server request internal URLs, reads internal services, AWS metadata, performs port scan, reads local files. SSRF can lead to RCE.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block internal IPs, localhost, and cloud metadata IPs. Use whitelist of allowed domains. Validate URL scheme (only http/https).',
        '<strong>Rule:</strong> Never fetch user-controlled URL without validation.',
        ],
        'code' => [
        '// SECURE - Block internal IPs',
        '<?php',
        '$url = $_POST[\'url\'];',
        '$parsed = parse_url($url);',
        'if ($parsed[\'scheme\'] != \'http\' && $parsed[\'scheme\'] != \'https\') { die(\'Only http/https allowed\'); }',
        '$ip = gethostbyname($parsed[\'host\']);',
        'if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {',
        '  die(\'Internal IP not allowed\');',
        '}',
        '$blocked = [\'169.254.169.254\', \'127.0.0.1\', \'localhost\'];',
        'if (in_array($parsed[\'host\'], $blocked)) { die(\'Blocked host\'); }',
        '$content = file_get_contents($url);',
        '?>',
        ],
        'steps' => [
        'Validate URL scheme - only allow http and https, block file://, gopher://, etc',
        'Block internal IPs: 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16.x.x',
        'Block cloud metadata IP: 169.254.169.254',
        'Resolve hostname to IP and check if internal',
        'Use whitelist of allowed domains if possible',
        'Set timeout for fetch to prevent long requests',
        'Disable redirects or check redirect URLs too',
        'Use DNS rebinding protection',
        ],
    ],
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null;
$fileFlash = null; // for file upload info

if (isset($_GET['internal']) && $_GET['internal'] === '1') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "INTERNAL_SSRF_OK\nservice=private\nport=" . ($_SERVER['SERVER_PORT'] ?? 'unknown') . "\n";
    echo "You accessed internal service via SSRF!\n";
    exit;
}

if (isset($_GET['metadata']) && $_GET['metadata'] === '1') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "INTERNAL_SSRF_OK\naws_metadata\nami-id: ami-12345678\ninstance-id: i-1234567890abcdef0\n";
    echo "iam/security-credentials/ -> admin-role\n";
    exit;
}

$serverPort = (int) ($_SERVER['SERVER_PORT'] ?? 8080);
$internalUrl = 'http://127.0.0.1:' . $serverPort . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/?internal=1';
$internalUrl2 = 'http://localhost:' . $serverPort . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/?internal=1';

// --- 1. Handle file upload (dummy, like other labs, but does NOT solve) ---
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '' && $file['error'] === UPLOAD_ERR_OK) {
    $safeName = basename($file['name']);
    $safeName = trim(str_replace(chr(0), '', $safeName));
    if ($safeName === '') $safeName = 'upload.bin';
    $dest = $uploadsDir . '/' . $safeName;
    if (file_exists($dest)) @unlink($dest);
    if (move_uploaded_file($file['tmp_name'], $dest)) {
        $link = 'uploads/' . rawurlencode($safeName);
        $linkLabel = 'View uploaded file';
        // Always 200, info, not ok - this lab is about URL SSRF
        http_response_code(200);
        $fileFlash = [
            'kind' => 'info',
            'title' => 'File uploaded (200) - but not the solution',
            'body' => 'فایل ' . $safeName . ' ذخیره شد ولی این لب با آپلود فایل حل نمیشه. این لب SSRF هست - باید از فرم پایینی URL بدی تا سرور برات fetch کنه. مثلا http://127.0.0.1:' . $serverPort . '/?internal=1'
        ];
        // If flash not set, use fileFlash as main
        if ($flash === null) {
            $flash = $fileFlash;
        }
    } else {
        http_response_code(200);
        $fileFlash = [
            'kind' => 'fail',
            'title' => 'Upload failed',
            'body' => 'Could not save file, but you can still try URL fetcher below.'
        ];
        if ($flash === null) $flash = $fileFlash;
    }
} elseif (isset($file) && $file['error'] !== UPLOAD_ERR_OK && $file['error'] !== UPLOAD_ERR_NO_FILE) {
    http_response_code(200);
    $fileFlash = [
        'kind' => 'fail',
        'title' => 'Upload error',
        'body' => 'Error code ' . (int)$file['error'] . ' - try again or use URL fetcher below.'
    ];
    if ($flash === null) $flash = $fileFlash;
}

// --- 2. Handle URL fetch (real SSRF logic) ---
$sourceUrl = trim((string) ($_POST['sourceUrl'] ?? ''));

function isInternalUrl($url) {
    $url = trim($url);
    if ($url === '') return false;
    if (stripos($url, 'file://') === 0) return true;
    $lower = strtolower($url);
    if (strpos($lower, '127.0.0.1') !== false) return true;
    if (strpos($lower, 'localhost') !== false) return true;
    if (strpos($lower, '0.0.0.0') !== false) return true;
    if (strpos($lower, '::1') !== false || strpos($lower, '[::1]') !== false) return true;
    if (strpos($lower, '169.254.169.254') !== false) return true;
    if (strpos($lower, '169.254.') !== false) return true;
    if (strpos($lower, 'metadata.google.internal') !== false) return true;
    if (preg_match('/10\.\d+\.\d+\.\d+/', $url)) return true;
    if (preg_match('/192\.168\.\d+\.\d+/', $url)) return true;
    if (preg_match('/172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+/', $url)) return true;
    if (preg_match('/127\.\d+\.\d+\.\d+/', $url)) return true;
    if (strpos($lower, '127.1') !== false) return true;
    if (strpos($url, '2130706433') !== false) return true;
    if (strpos($lower, '0x7f') !== false) return true;
    return false;
}

if ($sourceUrl !== '') {
    $isInternal = isInternalUrl($sourceUrl);
    $context = stream_context_create([
        'http' => [
            'timeout' => 3,
            'follow_location' => 0,
            'ignore_errors' => true,
            'header' => "User-Agent: FileUploadLab/1.0\r\n"
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ]);
    
    $data = @file_get_contents($sourceUrl, false, $context);
    
    if ($data === false && $isInternal) {
        if (stripos($sourceUrl, '169.254.169.254') !== false) {
            $data = "INTERNAL_SSRF_OK\naws_metadata\nami-id: ami-12345678\ninstance-id: i-1234567890abcdef0\nrequested_url: $sourceUrl\n";
        } elseif (stripos($sourceUrl, 'file://') === 0) {
            $filePath = substr($sourceUrl, 7);
            $realData = @file_get_contents($filePath);
            if ($realData !== false) {
                $data = $realData;
            } else {
                $data = "INTERNAL_SSRF_OK\nfile_read_simulated\npath: $filePath\ncontent: root:x:0:0:root:/root:/bin/bash\n";
            }
        } else {
            $data = "INTERNAL_SSRF_OK\nservice=private\nrequested_url: $sourceUrl\nserver_port: $serverPort\nmessage: You accessed internal service via SSRF to localhost/internal IP!\n";
        }
    }
    
    if ($data === false) {
        http_response_code(422);
        $flash = [
            'kind' => 'fail',
            'title' => 'Fetch failed',
            'body' => 'Could not fetch URL. Use internal payload with same port as lab: http://127.0.0.1:' . $serverPort . '/?internal=1 or http://localhost:' . $serverPort . '/ or http://169.254.169.254/ or file:///etc/passwd. Current lab port is ' . $serverPort . '.'
        ];
    } else {
        @file_put_contents($uploadsDir . '/remote.bin', $data);
        $link = 'uploads/remote.bin';
        $linkLabel = 'Open the fetched file';
        $extraOutput = $data;
        
        if (strpos($data, 'INTERNAL_SSRF_OK') !== false || $isInternal) {
            $flash = [
                'kind' => 'ok',
                'title' => 'Congratulations! You solved Scenario 15.',
                'body' => 'SSRF successful! Server fetched internal URL: ' . $sourceUrl
            ];
        } else {
            http_response_code(202);
            $flash = [
                'kind' => 'info',
                'title' => 'Remote file fetched',
                'body' => 'Fetched but not internal. Try: http://127.0.0.1:' . $serverPort . '/?internal=1 or http://localhost:' . $serverPort . '/ or http://169.254.169.254/ or file:///etc/passwd'
            ];
        }
    }
}

// Only set 422 for real fail from URL fetcher, not for file upload dummy
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && isset($sourceUrl) && $sourceUrl !== '' && http_response_code() === 200) {
    http_response_code(422);
}

?>
<!DOCTYPE html>
<html lang="en">
<?php include __DIR__ . '/../menu/header.php'; ?>
<body>
<?php include __DIR__ . '/../menu/navbar.php'; ?>

    <main class="bench">
        <span class="num">File Upload · SCENARIO 15 · UPLOAD</span>
        <h1>SSRF via Remote URL Upload</h1>
        <p>Server fetches URL without blocking localhost. Use SSRF to read internal services. File upload works but does not solve - use URL fetcher below.</p>

        <!-- PANEL 1: Standard file upload like other labs -->
        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
            <?php if ($fileFlash !== null): ?>
                <div class="flash <?= $fileFlash['kind'] ?>" role="status" style="margin-top:12px;">
                    <strong><?= htmlspecialchars($fileFlash['title'], ENT_QUOTES) ?></strong>
                    <?= htmlspecialchars($fileFlash['body'], ENT_QUOTES) ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- Helper text + URL fetcher -->
        <div class="panel upload-form" style="margin-top:18px; border-style:dashed;">
            <h2>یا میتونی URL بدی من برات پیدا کنم (SSRF)</h2>
            <p style="font-size:13px; opacity:0.85; margin:6px 0 10px;">
                این لب با آپلود فایل معمولی حل نمیشه. سرور قابلیت fetch کردن URL داره و جلوی IP های داخلی رو نمی‌گیره. 
                یه URL داخلی بده تا سرور برات بخونه. پورت لب: <strong><?= $serverPort ?></strong>
            </p>
            <p class="notice" style="font-size:12px;">نمونه URL های داخلی:</p>
            <ul style="font-size:0.85em; margin:8px 0; padding-left:20px; line-height:1.6;">
                <li><code><?= htmlspecialchars($internalUrl, ENT_QUOTES) ?></code></li>
                <li><code><?= htmlspecialchars($internalUrl2, ENT_QUOTES) ?></code></li>
                <li><code>http://127.0.0.1:<?= $serverPort ?>/</code> یا <code>http://localhost:<?= $serverPort ?>/</code></li>
                <li><code>http://169.254.169.254/latest/meta-data/</code></li>
                <li><code>file:///etc/passwd</code></li>
            </ul>
            <form action="" method="POST" style="margin-top:12px;">
                <label for="sourceUrl">File URL:</label>
                <input type="text" name="sourceUrl" id="sourceUrl" placeholder="http://127.0.0.1:<?= $serverPort ?>/?internal=1" required style="width:100%;" />
                <button class="primary-button" type="submit" style="margin-top:10px;">Fetch and save</button>
            </form>
        </div>

        <?php if ($flash !== null && $fileFlash === null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php elseif ($flash !== null && $fileFlash !== null && $flash !== $fileFlash): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($extraOutput !== null): ?>
            <pre class="panel hint-code" aria-label="Parser output" style="margin-top:16px;"><?= htmlspecialchars($extraOutput, ENT_QUOTES) ?></pre>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">
                    Next scenario &rarr;
                </a>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>" target="_blank" rel="noopener"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
