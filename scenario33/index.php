<?php
// File Upload · Scenario 33 — SVG SSRF via xlink
$pageTitle = 'SSRF via SVG File Upload (XLink)';
$scenarioNumber = 33;
$nextScenario = sprintf('../scenario%02d/', 34);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'SVG <image> tag can reference external URL via xlink:href.',
    'If server processes SVG (for example converts to PNG via ImageMagick), it fetches external URL.',
    'This can cause SSRF - server makes request to internal service.',
    'Goal: Upload SVG with external image reference to internal IP.',
];
$labHint = [
    'Create file ssrf.svg with: <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://127.0.0.1:80/" width="100" height="100"/></svg>',
    'Or use: <image href="http://169.254.169.254/latest/meta-data/"> for AWS metadata.',
    'Upload ssrf.svg via form. Use Burp Proxy.',
    'Server processes SVG and tries to fetch URL, shows result or makes request.',
    'Check Burp Collaborator or server logs for SSRF.',
    'Standard: SVG SSRF / XXE SSRF.',
];

$labRootCause = [
    'cwe' => 'CWE-918: SSRF via SVG',
    'owasp' => 'OWASP: SVG SSRF / XLink',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed SVG upload and server processes SVG with ImageMagick which fetches external URLs in <image> tag.</strong> SVG <image xlink:href="http://127.0.0.1"> makes server request internal URL.',
        '<strong>Mistake:</strong> Used ImageMagick to convert SVG to PNG without blocking external URL fetch. SVG image tag can reference http://, file://, etc. Server fetches it - SSRF.',
        '<strong>Why it happens:</strong> Developer did not know SVG can contain external references that ImageMagick will fetch.',
        ],
        'code' => [
        '// VULNERABLE - SVG SSRF!',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if ($ext == \'svg\' || $ext == \'png\') {',
        '  move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '  shell_exec(\'convert uploads/\' . $_FILES[\'file\'][\'name\'] . \' uploads/thumb.png\'); // ImageMagick fetches external URL in SVG!',
        '}',
        '?>',
        '<!-- Attacker uploads ssrf.svg: -->',
        '<!-- <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"> -->',
        '<!--   <image xlink:href="http://127.0.0.1:80/admin" width="100" height="100"/> -->',
        '<!-- </svg> -->',
        '<!-- ImageMagick convert fetches http://127.0.0.1:80/admin - SSRF! -->',
        ],
        'impact' => 'Attacker uploads SVG with external image reference to internal IP and server fetches it. SSRF reads internal services, AWS metadata, or local files via file://.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Disable external URL fetching in ImageMagick policy.xml. Sanitize SVG to remove xlink:href with http://, file://. Block SVG if not needed, or convert with secure policy.',
        '<strong>Rule:</strong> Block external references in SVG.',
        ],
        'code' => [
        '// SECURE - Block SVG SSRF',
        '<?php',
        '$allowed = [\'png\',\'jpg\',\'jpeg\',\'gif\']; // No svg',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if (!in_array($ext, $allowed)) { die(\'SVG not allowed\'); }',
        '// In /etc/ImageMagick/policy.xml:',
        '// <policy domain="coder" rights="none" pattern="URL" />',
        '// <policy domain="coder" rights="none" pattern="HTTP" />',
        '$svg = file_get_contents($_FILES[\'file\'][\'tmp_name\']);',
        'if (preg_match(\'/xlink:href\\s*=\\s*["\\\'](http|https|file):/i\', $svg)) {',
        '  die(\'External URL in SVG not allowed\');',
        '}',
        '?>',
        ],
        'steps' => [
        'Block SVG upload if not needed - safest',
        'If SVG needed, disable URL, HTTP, HTTPS coders in ImageMagick policy.xml',
        'Sanitize SVG to remove xlink:href with http://, https://, file://',
        'Use SVG sanitizer library',
        'Set ImageMagick policy to block external fetches',
        'Validate SVG structure',
        'Serve SVG as attachment, not inline',
        'Use allowlist for allowed SVG tags and attributes',
        ],
    ],
];
$link = null; $linkLabel = 'See the file'; $flash = null;
$file = $_FILES['fileToUpload'] ?? null;
if (isset($file) && $file['name'] !== '') {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $flash = ['kind'=>'fail','title'=>'Upload failed','body'=>'Error'];
    } else {
        $safeName = basename($file['name']);
        $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
        if ($ext !== 'svg') {
            $flash = ['kind'=>'fail','title'=>'Rejected','body'=>'Only SVG allowed.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Failed','body'=>'Could not save'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $fc = file_get_contents($uploadsDir.'/'.$safeName);
            if ((stripos($fc, 'xlink:href') !== false && stripos($fc, 'http://') !== false) || stripos($fc, 'http://127.0.0.1') !== false || stripos($fc, '169.254.169.254') !== false) {
                $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 33.','body'=>'SVG SSRF payload detected: xlink:href with internal URL.'];
            } else {
                $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'SVG saved but no SSRF payload. Use <image xlink:href="http://127.0.0.1/" />'];
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 33 · UPLOAD</span><h1>SVG SSRF (XLink)</h1><p>SVG image tag triggers SSRF. Upload SVG with external URL via Burp.</p>
<div class="panel upload-form"><h2>Upload SVG</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
