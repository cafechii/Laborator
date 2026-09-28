<?php
// File Upload · Scenario 23 — Web Shell Upload via Race Condition
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via Race Condition (TOCTOU)';
$scenarioNumber = 23;
$nextScenario = sprintf('../scenario%02d/', 24);
$uploadsDir = __DIR__ . '/uploads';

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'File is uploaded and made public before antivirus scan deletes it. There is a small time window to execute.',
    'Standard: Race Condition / TOCTOU via File Upload. Goal: Upload then quickly GET before deletion.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'This lab requires Burp Intruder or Turbo Intruder.',
    'In Burp Proxy, upload shell.php with <?php echo \'pwned\'; ?>.',
    'Server saves file then async scan deletes it after ~500ms. So you have race window.',
    'Setup: In Burp Repeater, upload file. Immediately in second tab, GET /scenario23/uploads/shell.php',
    'Use Burp Intruder: One payload to upload, second to GET file in loop, or use Turbo Intruder script.',
    'Send many rapid requests - one should hit before deletion and execute.',
    'PortSwigger: \'Web shell upload via race condition\'.',
];

$link      = null;
$linkLabel = 'See the file';
$flash     = null; // ['kind' => 'ok'|'fail', 'title' => ..., 'body' => ...]

function checkViruses(string $fileName): bool
{
    // Keep the file public while the simulated scan is running.
    usleep(2000000);
    return true;
}

function checkFileType(string $fileName): bool
{
    $imageFileType = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    return $imageFileType === 'jpg' || $imageFileType === 'png';
}

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                  'body'  => 'The server rejected the upload (error code ' . (int) $file['error'] . ').'];
    } else {
        $safeName = basename($file['name']);
        $dest     = $uploadsDir . '/' . $safeName;

        if (!move_uploaded_file($file['tmp_name'], $dest)) {
            $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                      'body'  => 'The server could not save the file, so the scan did not start.'];
        } else {
            // PortSwigger's flow: store first, scan second, delete only after
            // the checks fail. The race is the time before this branch ends.
            $virusCheckPassed = checkViruses($dest);
            $typeCheckPassed  = checkFileType($safeName);

            if ($virusCheckPassed && $typeCheckPassed) {
                $link = 'uploads/' . rawurlencode($safeName);
                http_response_code(202);
                $flash = ['kind' => 'info', 'title' => 'Image uploaded',
                          'body'  => 'The image passed validation and was kept. Use shell.php to test the race.'];
            } else {
                if (is_file($dest)) {
                    unlink($dest);
                }
                http_response_code(403);
                $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                          'body'  => 'Sorry, only JPG and PNG files are allowed.'];
            }
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
        <span class="num">File Upload · SCENARIO 23 · UPLOAD</span>
        <h1>Race Condition (TOCTOU)</h1>
        <p>File exists briefly before AV deletes it. Use Burp Intruder to race and execute.</p>

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
