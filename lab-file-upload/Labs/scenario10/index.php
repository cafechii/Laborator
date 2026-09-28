<?php
// File Upload · Scenario 10 — Reflected Filename XSS
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Stored XSS via File Name Upload';
$scenarioNumber = 10;
$nextScenario = sprintf('../scenario%02d/', 11);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'The application reflects the uploaded filename without HTML escaping.',
    'An attacker can inject <script> or <img onerror> via filename.',
    'Standard: XSS via File Name / Stored XSS in upload. Goal: <img src=x onerror=alert(1)>.png',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Open Burp Suite > Proxy > Intercept ON.',
    'Create any file (e.g., test.png) but set filename to <img src=x onerror=alert(document.domain)>.png',
    'In Burp, intercept the upload request. Verify filename contains XSS payload in Content-Disposition.',
    'Forward. The response page will echo filename unescaped and trigger XSS.',
    'Check browser - alert should fire. Use Burp to confirm payload is stored/reflected.',
    'PortSwigger: \'Stored XSS via file upload filename\'.',
];

$link      = null;
$linkLabel = 'See the file';
$flash     = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                  'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').'];
    } else {
        $reflected = 'uploads/' . $file['name'];

        if (preg_match('/<[^>]*(onerror|onload|onclick|script)[^>]*>/i', $file['name'])) {
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 10.',
                      'body'  => 'The filename was reflected without escaping.'];
        } else {
            $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                      'body'  => 'The filename was displayed, but it did not contain executable markup.'];
        }
    }
}

// Keep the verdict meaningful to Burp as well as to the page.
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
        <span class="num">File Upload · SCENARIO 10 · UPLOAD</span>
        <h1>Stored XSS via Filename</h1>
        <p>Filename reflected without escaping. Inject XSS via filename using Burp.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
        </div>

        <?php if (isset($reflected) && $reflected !== null): ?>
            <div class="panel">
                <h2>Answer</h2>
                <!-- the flaw, on purpose: the name is echoed without escaping -->
                <p class="notice error">Your file <?= $reflected ?> was not uploaded!</p>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?>
            <div class="next-scenario">
                <a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>" target="_blank" rel="noopener">
                    Next scenario &rarr;
                </a>
            </div>
        <?php endif; ?>

        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
        <?php endif; ?>

        <?php if ($link !== null): ?>
            <p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p>
        <?php endif; ?>
    </main>

<?php include __DIR__ . '/../menu/footer.php'; ?>
</body>
</html>
