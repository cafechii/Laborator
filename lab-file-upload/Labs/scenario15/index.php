<?php
// File Upload · Scenario 15 — Remote URL Upload SSRF
// This page is self-contained: validation, description, hint, verdict, and storage.

$pageTitle = 'SSRF via Remote URL File Upload';
$scenarioNumber = 15;
$nextScenario = sprintf('../scenario%02d/', 16);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'Application allows providing a remote URL to fetch file from, without restricting internal IPs.',
    'Attacker can make server fetch http://127.0.0.1 or http://169.254.169.254 for cloud metadata.',
    'Standard: SSRF via File Upload / Remote URL Upload.',
];

$labHint = [
    'Look at page: it shows an input for remote URL or example internal URL.',
    'In Burp Proxy, intercept the POST request that contains URL parameter.',
    'Try URL: http://127.0.0.1:8080/scenario15/?internal=1 (lab\'s internal endpoint) or http://169.254.169.254/latest/meta-data/ for AWS.',
    'Send to Repeater. Change url parameter to http://127.0.0.1:8080/scenario15/?internal=1',
    'Server will fetch internal URL and show INTERNAL_SSRF_OK.',
    'Congratulations when SSRF to internal service succeeds. PortSwigger: \'SSRF via file upload\'.',
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null; // ['kind' => 'ok'|'info'|'fail', 'title' => ..., 'body' => ...]

if (isset($_GET['internal']) && $_GET['internal'] === '1') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "INTERNAL_SSRF_OK\nservice=private\n";
    exit;
}

$serverPort = (int) ($_SERVER['SERVER_PORT'] ?? 8080);
$internalUrl = 'http://127.0.0.1:' . $serverPort . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/') . '/?internal=1';
$sourceUrl = trim((string) ($_POST['sourceUrl'] ?? ''));
if ($sourceUrl !== '') {
    $context = stream_context_create(['http' => ['timeout' => 3, 'follow_location' => 0]]);
    $data = @file_get_contents($sourceUrl, false, $context);
    if ($data === false) {
        http_response_code(422);
        $flash = ['kind' => 'fail', 'title' => 'Fetch failed', 'body' => 'The server could not fetch that URL.'];
    } else {
        file_put_contents($uploadsDir . '/remote.bin', $data);
        $link = 'uploads/remote.bin';
        if (strpos($data, 'INTERNAL_SSRF_OK') !== false || stripos($sourceUrl, 'file://') === 0 || stripos($sourceUrl, '127.0.0.1') !== false || stripos($sourceUrl, 'localhost') !== false) {
            $extraOutput = $data;
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 15.', 'body' => 'The server fetched the internal target successfully.'];
        } else {
            http_response_code(202);
            $flash = ['kind' => 'info', 'title' => 'Remote file fetched', 'body' => 'The URL was fetched, but it was not the internal target.'];
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
        <span class="num">File Upload · SCENARIO 15 · UPLOAD</span>
        <h1>SSRF via Remote URL Upload</h1>
        <p>Server fetches user-supplied URL without restriction. Use Burp to SSRF internal services.</p>

        <div class="panel upload-form">
            <h2>Fetch a remote file</h2>
            <p class="notice">Internal test URL: <code><?= htmlspecialchars($internalUrl, ENT_QUOTES) ?></code></p>
            <form action="" method="POST">
                <label for="sourceUrl">File URL:</label>
                <input type="url" name="sourceUrl" id="sourceUrl" required />
                <button class="primary-button" type="submit">Fetch and save</button>
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
