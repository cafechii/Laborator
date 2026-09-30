<?php
// File Upload · Scenario 21 — Image Polyglot (Metadata Payload)
//
// Intended flaw: one check, one way around it. A wrong payload can never
// write outside this scenario directory.

$pageTitle = 'Web Shell Upload via Polyglot File (Image Metadata)';
$scenarioNumber = 21;
$nextScenario = sprintf('../scenario%02d/', 22);
$uploadsDir = __DIR__ . '/uploads';

// A real polyglot keeps the PHP marker inside a PNG metadata chunk. This
// accepts the text metadata produced by ExifTool and compressed PNG text chunks,
// but does not accept PHP merely appended after IEND.
function pngMetadataHasPhpPayload(string $path): bool
{
    $data = @file_get_contents($path);
    $signature = "\x89PNG\r\n\x1a\n";

    if ($data === false || !str_starts_with($data, $signature)) {
        return false;
    }

    $length = strlen($data);
    $offset = 8;

    while ($offset + 12 <= $length) {
        $chunkLengthBytes = substr($data, $offset, 4);
        $unpacked = unpack('N', $chunkLengthBytes);
        if ($unpacked === false) {
            return false;
        }
        $chunkLength = $unpacked[1];

        if ($chunkLength > $length - $offset - 12) {
            return false;
        }

        $type = substr($data, $offset + 4, 4);
        $chunkData = substr($data, $offset + 8, $chunkLength);
        $metadata = $chunkData;

        if ($type === 'zTXt') {
            $keywordEnd = strpos($chunkData, "\0");
            if ($keywordEnd !== false && isset($chunkData[$keywordEnd + 1]) && ord($chunkData[$keywordEnd + 1]) === 0) {
                $decoded = @gzuncompress(substr($chunkData, $keywordEnd + 2));
                if ($decoded !== false) {
                    $metadata = $decoded;
                }
            }
        } elseif ($type === 'iTXt') {
            $keywordEnd = strpos($chunkData, "\0");
            if ($keywordEnd !== false && strlen($chunkData) > $keywordEnd + 2 && ord($chunkData[$keywordEnd + 1]) === 1) {
                $languageStart = $keywordEnd + 3;
                $languageEnd = strpos($chunkData, "\0", $languageStart);
                if ($languageEnd !== false) {
                    $translatedEnd = strpos($chunkData, "\0", $languageEnd + 1);
                    if ($translatedEnd !== false) {
                        $decoded = @gzuncompress(substr($chunkData, $translatedEnd + 1));
                        if ($decoded !== false) {
                            $metadata = $decoded;
                        }
                    }
                }
            }
        }

        if (in_array($type, ['tEXt', 'zTXt', 'iTXt', 'eXIf'], true)
            && strpos($metadata, '<?php') !== false) {
            return true;
        }

        $offset += 12 + $chunkLength;
        if ($type === 'IEND') {
            break;
        }
    }

    return false;
}

if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

// Shown in the Description drawer (../menu/navbar.php).
$labDescription = [
    'A polyglot file is valid as both image and PHP. Embed PHP in EXIF or PNG tEXt chunk.',
    'Server validates image via getimagesize() but PHP code remains in metadata and executes.',
    'Standard: Polyglot / Image Payload / Shell in Image.',
];

// Read by ../menu/navbar.php to fill the hint drawer. A step may carry code.
$labHint = [
    'Create a valid 1x1 PNG, then inject PHP in comment: Use exiftool: exiftool -Comment=\'<?php echo "pwned"; ?>\' image.png',
    'Or manually create polyglot: PNG header + PHP payload in tEXt chunk.',
    'Upload polyglot.png.php or just polyglot.png if server renames to .php? In this lab, upload as shell.php.png with PNG header + PHP.',
    'In Burp Proxy, intercept and ensure file starts with PNG magic but contains <?php.',
    'Server getimagesize() will pass, but file contains PHP.',
    'Click link - if executed, polyglot works. PortSwigger: \'Web shell upload via polyglot\'.',
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
        $size = @getimagesize($file['tmp_name']);

        if (!$size || $size[0] < 1 || $size[1] < 1 || ($size['mime'] ?? '') !== 'image/png') {
            $flash = ['kind' => 'fail', 'title' => 'Upload rejected',
                      'body'  => 'The file is not a valid PNG image.'];
        } else {
            $safeName      = basename($file['name']);
            $hasPhpPayload = pngMetadataHasPhpPayload($file['tmp_name']);

            if (!move_uploaded_file($file['tmp_name'], $uploadsDir . '/' . $safeName)) {
                $flash = ['kind' => 'fail', 'title' => 'Upload failed',
                          'body'  => 'The server could not save the file.'];
            } else {
                $link = 'uploads/' . rawurlencode($safeName);

                if (strtolower(pathinfo($safeName, PATHINFO_EXTENSION)) === 'php' && $hasPhpPayload) {
                    $flash = ['kind' => 'ok', 'title' => 'Congratulations! You solved Scenario 21.',
                              'body'  => 'The file passed the PNG check and contains a PHP payload.'];
                } else {
                    $flash = ['kind' => 'fail', 'title' => 'Not solved yet',
                              'body'  => 'The PNG check passed, but the file has no PHP payload.'];
                }
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
        <span class="num">File Upload · SCENARIO 21 · UPLOAD</span>
        <h1>Image Polyglot (Shell in Metadata)</h1>
        <p>Valid image containing PHP in EXIF/PNG chunk. Create polyglot and upload via Burp.</p>

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
