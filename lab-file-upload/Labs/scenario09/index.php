<?php
// File Upload · Scenario 09 — Null Byte Truncation
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via Null Byte Injection';
$scenarioNumber = 9;
$nextScenario = sprintf('../scenario%02d/', 10);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'Legacy PHP/C code truncates filename at null byte %00. Validation sees shell.php%00.jpg as .jpg (allowed), but filesystem saves as shell.php.',
    'Modern PHP 7+ fixed this, but lab simulates vulnerable behavior via urldecode + strtok.',
    'Standard: Null Byte Bypass / %00 Truncation (WSTG). Goal: shell.php%00.jpg',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'In Burp Suite, turn Proxy > Intercept ON.',
    'Upload shell.php normally - it will be blocked.',
    'Send POST /scenario09/ to Burp Repeater.',
    'Change filename to shell.php%00.jpg (literally percent-zero-zero). The lab does urldecode().',
    'Alternatively, try shell.php%00.png or use Burp Decoder to insert null byte (0x00).',
    'Content: <?php echo \'pwned\'; ?>',
    'Send. Server checks extension after urldecode? It sees .jpg but truncates at null and saves as .php.',
    'Click link to execute. PortSwigger: \'Web shell upload via null byte\'. Note: Requires Repeater, not just browser.',
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
        $decoded   = urldecode($file['name']);
        $checked   = strtolower(pathinfo($decoded, PATHINFO_EXTENSION));
        $truncated = strtok($decoded, "\0");
        // Keep traversal out of this lab: only the null-byte truncation should
        // change the final stored name.
        $stored    = basename($truncated !== false ? $truncated : $decoded);

        if (!in_array($checked, ['jpg', 'jpeg', 'png'], true)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'The filename does not end in .jpg or .png.'];
        } elseif ($stored === '' || !preg_match('/\.php$/i', $stored) || !move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $stored)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The truncated filename is not a PHP filename.'];
        } else {
            $link  = 'uploads/' . rawurlencode($stored);
            $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 09.',
                      'body'  => 'The check saw .png, but storage used the truncated .php name.'];
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
        <span class="num">File Upload · SCENARIO 09 · UPLOAD</span>
        <h1>Null Byte Injection</h1>
        <p>Validation sees .jpg, filesystem truncates at %00 and saves as .php. Use Burp Repeater.</p>

        <div class="panel upload-form">
            <h2>Upload an Image!</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select a file:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" />
                <button class="primary-button" type="submit" name="submit" value="Upload">Upload</button>
            </form>
        </div>


        <?php if ($flash !== null): ?>
            <div class="flash <?= $flash['kind'] ?>" role="status">
                <strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong>
                <?= htmlspecialchars($flash['body'], ENT_QUOTES) ?>
            </div>
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
