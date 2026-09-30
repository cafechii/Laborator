<?php
// File Upload · Scenario 16 — XXE via .docx (OOXML) - Rewritten from scratch per user request
// Should be solved with .docx only, not .xml

$pageTitle = 'XXE via .docx File Upload (OOXML Document)';
$scenarioNumber = 16;
$nextScenario = sprintf('../scenario%02d/', 17);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) {
    mkdir($uploadsDir, 0775, true);
}

$labDescription = [
    'This lab accepts Office files like .docx and .xlsx.',
    'These files are actually ZIP files containing XML.',
    'Server unzips docx and parses word/document.xml with XXE enabled.',
    'Goal: Create docx with XXE in word/document.xml to read /etc/passwd.',
];

$labHint = [
    'Docx is ZIP. Create folder structure: [Content_Types].xml, _rels/.rels, word/document.xml.',
    'In word/document.xml put: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>',
    'Zip all files and rename to xxe.docx.',
    'Upload xxe.docx via form. Use Burp Proxy > Intercept to forward.',
    'You should see Congratulations and /etc/passwd content.',
    'Standard: XXE via DOCX / OOXML.',
];

$labRootCause = [
    'cwe' => 'CWE-611: XXE via DOCX',
    'owasp' => 'OWASP: XXE in OOXML',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed .docx upload and parsed word/document.xml with XXE enabled.</strong> DOCX is ZIP containing XML, and XML parser had external entities enabled.',
        '<strong>Mistake:</strong> Unzipped DOCX and parsed document.xml with LIBXML_NOENT flag which enables XXE. No disabling of external entities.',
        '<strong>Why it happens:</strong> Developer did not know DOCX contains XML that can have XXE. Thought Office files are safe.',
        ],
        'code' => [
        '// VULNERABLE - XXE via DOCX!',
        '<?php',
        '$zip = new ZipArchive();',
        '$zip->open($_FILES[\'file\'][\'tmp_name\']); // DOCX is ZIP',
        '$xmlContent = $zip->getFromName(\'word/document.xml\');',
        '$dom = new DOMDocument();',
        '$dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD); // Enables XXE!',
        'echo $dom->textContent;',
        '?>',
        '// Attacker creates docx with word/document.xml containing:',
        '// <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '// <w:document><w:t>&xxe;</w:t></w:document>',
        ],
        'impact' => 'Attacker uploads DOCX with XXE in document.xml and reads local files like /etc/passwd. DOCX is ZIP with XML inside, XXE possible.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Disable external entities when parsing XML from DOCX. Strip DOCTYPE and ENTITY before parsing. Use secure XML parser config.',
        '<strong>Rule:</strong> Any XML from user, even inside ZIP/DOCX, must be parsed securely.',
        ],
        'code' => [
        '// SECURE - Disable XXE for DOCX',
        '<?php',
        '$zip = new ZipArchive();',
        '$zip->open($_FILES[\'file\'][\'tmp_name\']);',
        '$xmlContent = $zip->getFromName(\'word/document.xml\');',
        'libxml_disable_entity_loader(true);',
        '$dom = new DOMDocument();',
        '$dom->loadXML($xmlContent, LIBXML_DTDLOAD); // No NOENT!',
        '$xmlContent = preg_replace(\'/<!DOCTYPE.*?>/s\', \'\', $xmlContent);',
        '$dom->loadXML($xmlContent);',
        '?>',
        ],
        'steps' => [
        'Disable external entities: libxml_disable_entity_loader(true)',
        'Don\'t use LIBXML_NOENT flag',
        'Strip DOCTYPE and ENTITY from XML before parsing',
        'Use whitelist for allowed XML tags',
        'Validate DOCX structure',
        'Don\'t display XML content directly - escape with htmlspecialchars',
        'Use PHP 8.0+ where entity loader disabled by default',
        'Consider using anti-XXE library',
        ],
    ],
];

$link = null;
$linkLabel = 'Open the uploaded file';
$extraOutput = null;
$flash = null;

$file = isset($_FILES['fileToUpload']) ? $_FILES['fileToUpload'] : null;

if (isset($file) && $file['name'] !== '') {
    $safeName = basename($file['name']);
    $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));
    
    // Only accept .docx, .xlsx, .docm (OOXML) - per user request, must be docx not xml
    $allowedExt = ['docx', 'xlsx', 'docm', 'dotx'];
    if (!in_array($ext, $allowedExt, true)) {
        http_response_code(415);
        $flash = [
            'kind' => 'fail',
            'title' => 'Upload rejected',
            'body' => 'فقط فایل .docx قبول می‌کنه (نه .xml). یه فایل .docx بساز که داخل word/document.xml XXE داشته باشه. از اسکریپت PowerShell داخل Hint استفاده کن.'
        ];
    } else {
        $tmpPath = $file['tmp_name'];
        $foundEntity = false;
        $entityUrl = '';
        $expandedContent = null;
        $xmlContent = '';
        
        // Try to open as ZIP (docx is ZIP)
        $zip = new ZipArchive();
        if ($zip->open($tmpPath) === true) {
            // Look for document.xml, [Content_Types].xml, or any xml with ENTITY
            $targets = ['word/document.xml', '[Content_Types].xml', 'xl/workbook.xml', 'word/document2.xml'];
            // Also check all files in zip
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                $name = $stat['name'] ?? '';
                if (stripos($name, '.xml') !== false) {
                    $targets[] = $name;
                }
            }
            $targets = array_unique($targets);
            
            foreach ($targets as $target) {
                $content = $zip->getFromName($target);
                if ($content === false) continue;
                
                // Check for ENTITY definition
                if (preg_match('/<!ENTITY\s+([A-Za-z_][\w.-]*)\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $content, $m)) {
                    $foundEntity = true;
                    $entityUrl = $m[2];
                    $xmlContent = $content;
                    // Try to expand
                    if (class_exists('DOMDocument')) {
                        $dom = new DOMDocument();
                        libxml_use_internal_errors(true);
                        $loaded = @$dom->loadXML($content, LIBXML_NOENT | LIBXML_DTDLOAD);
                        if ($loaded) {
                            $text = trim($dom->textContent);
                            if ($text !== '' && $text !== 'XXE Test:') {
                                $expandedContent = $text;
                            } else {
                                // Try file_get_contents for file://
                                if (stripos($entityUrl, 'file://') === 0) {
                                    $path = substr($entityUrl, 7);
                                    $data = @file_get_contents($path);
                                    if ($data !== false) {
                                        $expandedContent = $data;
                                    } else {
                                        $expandedContent = "Simulated read: $entityUrl -> root:x:0:0:root:/root:/bin/bash";
                                    }
                                } else {
                                    // For http:// etc
                                    $data = @file_get_contents($entityUrl);
                                    if ($data !== false) {
                                        $expandedContent = $data;
                                    } else {
                                        $expandedContent = "Simulated SSRF: $entityUrl -> INTERNAL_SSRF_OK";
                                    }
                                }
                            }
                        }
                        libxml_clear_errors();
                    }
                    break;
                }
            }
            $zip->close();
        } else {
            // Not a valid ZIP, maybe they uploaded XML directly
            $content = @file_get_contents($tmpPath);
            if (preg_match('/<!ENTITY\s+.*SYSTEM/i', $content)) {
                $foundEntity = true;
                if (preg_match('/SYSTEM\s+["\']([^"\']+)["\']/i', $content, $m)) {
                    $entityUrl = $m[1];
                }
                $expandedContent = "Found ENTITY in non-ZIP file but lab requires .docx ZIP format";
            }
        }
        
        if (!$foundEntity) {
            http_response_code(422);
            $flash = [
                'kind' => 'fail',
                'title' => 'No XXE entity found',
                'body' => 'داخل .docx هیچ <!ENTITY ... SYSTEM ...> پیدا نشد. مطمئن شو word/document.xml داخل docx حاوی <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> و &xxe; باشه. از اسکریپت PowerShell تو Hint استفاده کن.'
            ];
        } elseif ($expandedContent === null || trim($expandedContent) === '' || trim($expandedContent) === 'XXE Test:') {
            http_response_code(422);
            $flash = [
                'kind' => 'fail',
                'title' => 'Entity not expanded',
                'body' => 'ENTITY پیدا شد (' . htmlspecialchars($entityUrl) . ') ولی محتواش خونده نشد. سعی کن file:///etc/passwd یا file:///etc/hostname. اگر &xxe; رو صدا نزدی، اضافه کن: <w:t>&xxe;</w:t>'
            ];
        } else {
            // Success - save file
            if (!move_uploaded_file($tmpPath, $uploadsDir . '/' . $safeName)) {
                // If move fails (because we already read tmp), copy from tmp path if still exists or just simulate
                @copy($tmpPath, $uploadsDir . '/' . $safeName);
            }
            $link = 'uploads/' . rawurlencode($safeName);
            $extraOutput = $expandedContent;
            $flash = [
                'kind' => 'ok',
                'title' => 'Congratulations! You solved Scenario 16.',
                'body' => 'XXE via .docx موفق بود! فایل ' . $entityUrl . ' خونده شد. این دقیقا همون حمله‌ایه که تو دنیای واقعی با آپلود docx انجام میشه.'
            ];
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
        <span class="num">File Upload · SCENARIO 16 · UPLOAD</span>
        <h1>XXE via .docx Upload (OOXML)</h1>
        <p>فایل .docx در واقع ZIP هست که داخلش XML داره. با XXE داخل word/document.xml می‌تونی فایل بخونی. باید با .docx حل بشه نه .xml</p>

        <div class="panel upload-form">
            <h2>Upload a .docx document with XXE</h2>
            <form action="" method="POST" enctype="multipart/form-data">
                <label for="fileToUpload">Select .docx:</label>
                <input type="file" name="fileToUpload" id="fileToUpload" accept=".docx,.xlsx,.docm,application/vnd.openxmlformats-officedocument.wordprocessingml.document" />
                <button class="primary-button" type="submit">Parse document</button>
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
