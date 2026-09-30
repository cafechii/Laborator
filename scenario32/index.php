<?php
// File Upload · Scenario 32 — SSI Injection via .shtml
$pageTitle = 'Server-Side Includes Injection via .shtml Upload';
$scenarioNumber = 32;
$nextScenario = sprintf('../scenario%02d/', 33);
$uploadsDir = __DIR__ . '/uploads';
if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0775, true);
$labDescription = [
    'SHTML files support Server-Side Includes (SSI).',
    'Directives like <!--#exec cmd="id" --> or <!--#include virtual="/etc/passwd" --> execute commands.',
    'If server has mod_include enabled, SHTML files are parsed.',
    'This is Apache Only.',
    'Goal: Upload shell.shtml with SSI payload.',
];
$labHint = [
    'This lab works only on Apache with SSI enabled.',
    'Create file shell.shtml with: <!--#exec cmd="id" -->',
    'Or: <!--#exec cmd="echo SSI_OK" -->',
    'Upload via Burp Suite - filename shell.shtml',
    'Server if mod_include is enabled, will execute command.',
    'Click link - you should see uid or SSI_OK.',
    'Standard: SSI Injection / Server Side Includes.',
];

$labRootCause = [
    'cwe' => 'CWE-94: SSI Injection',
    'owasp' => 'OWASP: Server Side Includes',
    'bad' => [
        'explanation' => [
        '<strong>Programmer allowed .shtml upload and server has mod_include enabled.</strong> SHTML files support Server-Side Includes like <!--#exec cmd="id" --> which executes command.',
        '<strong>Mistake:</strong> Allowed .shtml, .shtm, .stm extensions without knowing they can execute commands via SSI. Apache with mod_include parses SHTML and runs exec directive.',
        '<strong>Why it happens:</strong> Developer thought SHTML is just HTML, but SHTML with SSI can run shell commands. Apache Only.',
        ],
        'code' => [
        '// VULNERABLE - Allows SHTML with SSI!',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        'if ($ext == \'shtml\' || $ext == \'html\' || $ext == \'png\') {',
        '  move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $_FILES[\'file\'][\'name\']);',
        '}',
        '?>',
        '<!-- Attacker uploads shell.shtml with: -->',
        '<!-- <!--#exec cmd="id" --> -->',
        '<!-- Request /uploads/shell.shtml - Apache mod_include parses SSI and runs id command! RCE! -->',
        ],
        'impact' => 'Attacker uploads shell.shtml with SSI exec directive and gets RCE when Apache parses SHTML with mod_include. SSI can execute commands or include files. Apache Only.',
    ],
    'good' => [
        'explanation' => [
        '<strong>Fix:</strong> Block .shtml, .shtm, .stm extensions. Disable mod_include or disable exec in SSI with IncludesNOEXEC. Don\'t allow server-parsed files upload.',
        '<strong>Rule:</strong> Block SHTML and disable SSI exec.',
        ],
        'code' => [
        '// SECURE - Block SHTML',
        '<?php',
        '$ext = strtolower(pathinfo($_FILES[\'file\'][\'name\'], PATHINFO_EXTENSION));',
        '$blocked = [\'shtml\',\'shtm\',\'stm\',\'sht\',\'ssi\'];',
        'if (in_array($ext, $blocked)) { die(\'SHTML not allowed\'); }',
        'if (!in_array($ext, [\'png\',\'jpg\',\'jpeg\',\'gif\'])) { die(\'Invalid\'); }',
        '$newName = bin2hex(random_bytes(16)) . \'.\' . $ext;',
        'move_uploaded_file($_FILES[\'file\'][\'tmp_name\'], \'uploads/\' . $newName);',
        '?>',
        '# Apache config secure:',
        '# Options -Includes - to disable SSI',
        '# Or: Options IncludesNOEXEC - allows include but not exec',
        ],
        'steps' => [
        'Block .shtml, .shtm, .stm, .sht extensions',
        'Disable mod_include in Apache: Options -Includes',
        'Or use IncludesNOEXEC to allow include but block exec',
        'Set AddType text/plain for shtml to prevent execution',
        'Whitelist only image extensions',
        'Randomize filename',
        'Disable PHP and SSI execution in uploads folder',
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
        if (!in_array($ext, ['shtml','shtm','stm'], true)) {
            $flash = ['kind'=>'fail','title'=>'Upload rejected','body'=>'Only .shtml allowed. Try SSI payload.'];
        } elseif (!move_uploaded_file($file['tmp_name'], $uploadsDir.'/'.$safeName)) {
            $flash = ['kind'=>'fail','title'=>'Failed','body'=>'Could not save'];
        } else {
            $link = 'uploads/'.rawurlencode($safeName);
            $fc = file_get_contents($uploadsDir.'/'.$safeName);
            if (stripos($fc, '<!--#exec') !== false || stripos($fc, '<!--#include') !== false) {
                $flash = ['kind'=>'ok','title'=>'Congratulations! You solved Scenario 32.','body'=>'SSI directive found in '.$safeName];
            } else {
                $flash = ['kind'=>'fail','title'=>'Not solved','body'=>'No SSI directive. Use <!--#exec cmd="id" -->'];
            }
        }
    }
}
if ($flash !== null && ($flash['kind'] ?? '') === 'fail' && http_response_code() === 200) http_response_code(422);
?>
<!DOCTYPE html><html lang="en"><?php include __DIR__ . '/../menu/header.php'; ?><body><?php include __DIR__ . '/../menu/navbar.php'; ?>
<main class="bench"><span class="num">File Upload · SCENARIO 32 · UPLOAD</span><h1>SSI Injection (.shtml)</h1><p>SHTML supports SSI exec. Upload malicious .shtml via Burp.</p>
        <div class="panel" style="background:rgba(255,60,60,0.15); border:1px solid #ff3c3c; border-radius:8px; padding:12px; margin-bottom:16px; text-align:center;">
            <strong style="color:#ff6b6b;">⚠️ Apache Only</strong>
        </div>
<div class="panel upload-form"><h2>Upload .shtml</h2><form action="" method="POST" enctype="multipart/form-data"><input type="file" name="fileToUpload" /><button class="primary-button" type="submit">Upload</button></form></div>
<?php if ($flash !== null): ?><div class="flash <?= $flash['kind'] ?>"><strong><?= htmlspecialchars($flash['title'], ENT_QUOTES) ?></strong><?= htmlspecialchars($flash['body'], ENT_QUOTES) ?></div><?php endif; ?>
<?php if ($flash !== null && ($flash['kind'] ?? '') === 'ok' && $nextScenario !== null): ?><div class="next-scenario"><a class="primary-button" href="<?= htmlspecialchars($nextScenario, ENT_QUOTES) ?>">Next &rarr;</a></div><?php endif; ?>
<?php if ($link !== null): ?><p class="notice ok"><a href="<?= htmlspecialchars($link, ENT_QUOTES) ?>"><?= htmlspecialchars($linkLabel, ENT_QUOTES) ?></a></p><?php endif; ?></main><?php include __DIR__ . '/../menu/footer.php'; ?></body></html>
