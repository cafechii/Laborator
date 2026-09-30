<!-- Background layers -->
<div class="background-grid" aria-hidden="true"></div>

<!-- Topbar -->
<header class="topbar">
    <div class="container topbar-content">
        <a class="logo" href="/menu/">
            <span class="logo-symbol" aria-hidden="true">
                <svg viewBox="0 0 24 24"><path d="M13 2 4 14h6l-1 8 10-12h-6z" /></svg>
            </span>
            <span>
                <strong>File Upload</strong>
                <small>private test environment</small>
            </span>
        </a>
        <div class="system-state">
            <span class="status-dot" aria-hidden="true"></span>
            all systems operational
        </div>
    </div>
</header>

<!-- Bench bar -->
<div class="bench-bar">
    <div class="bench-bar-inner">
        <div class="bench-bar-left">
            <button class="hint-button desc-button" type="button" id="desc-toggle" aria-expanded="false" aria-controls="desc-box">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h11"/></svg>
                Description
            </button>
            <button class="hint-button" type="button" id="hint-toggle" aria-expanded="false" aria-controls="hint-box">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a7 7 0 0 0-4 12.7.9.9 0 0 1 .3.6V17a2 2 0 0 0 2 2h3.4a2 2 0 0 0 2-2v-1.7a.9.9 0 0 1 .3-.6A7 7 0 0 0 12 2Zm-2.6 19h5.2a1.3 1.3 0 0 1-1.3 1h-2.6a1.3 1.3 0 0 1-1.3-1Z"/></svg>
                Hint
            </button>
            <button class="hint-button" type="button" id="root-toggle" aria-expanded="false" aria-controls="root-box" style="border-color: rgba(239,68,68,0.45); background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(220,38,38,0.1)); color: #fca5a5;">
                <svg viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                Root Cause
            </button>
        </div>
        <a class="primary-button" href="/menu/">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5m7-7-7 7 7 7"/></svg>
            Back to menu
        </a>
    </div>
</div>

<!-- Description drawer -->
<div class="hint-box desc-box" id="desc-box" hidden>
    <h2>Description</h2>
<?php if (!empty($labDescription)): ?>
    <?php foreach ((array) $labDescription as $para): ?>
        <p><?= htmlspecialchars($para, ENT_QUOTES) ?></p>
    <?php endforeach; ?>
<?php else: ?>
    <p class="hint-empty">no description written for this scenario yet</p>
<?php endif; ?>
</div>

<!-- Hint drawer -->
<div class="hint-box" id="hint-box" hidden>
    <h2>Hint</h2>
<?php if (!empty($labHint)): ?>
    <?php if (is_array($labHint)): ?>
        <ol>
            <?php foreach ($labHint as $step):
                $text = is_array($step) ? ($step['text'] ?? '') : $step;
                $code = is_array($step) ? ($step['code'] ?? []) : [];
            ?>
                <li>
                    <?php if ($text !== ''): ?><?= htmlspecialchars($text, ENT_QUOTES) ?><?php endif; ?>
                    <?php if ($code): ?>
                        <pre class="hint-code"><code><?= htmlspecialchars(implode("\n", (array) $code), ENT_QUOTES) ?></code></pre>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ol>
    <?php else: ?>
        <p><?= htmlspecialchars($labHint, ENT_QUOTES) ?></p>
    <?php endif; ?>
<?php else: ?>
    <p class="hint-empty">no hint written for this scenario yet</p>
<?php endif; ?>
</div>

<!-- Root Cause drawer - IMPROVED BEAUTIFUL VERSION -->
<style>
.root-cause-box { 
    border: 1px solid rgba(239,68,68,0.25) !important; 
    background: linear-gradient(135deg, rgba(30,12,12,0.8), rgba(20,10,15,0.7)) !important; 
    backdrop-filter: blur(12px);
    box-shadow: 0 8px 32px rgba(239,68,68,0.08);
}
.root-cause-box h2 { 
    color: #f87171 !important; 
    font-size: 20px !important;
    letter-spacing: -0.3px;
}

/* Section container - beautiful */
.rc-section { 
    margin-bottom: 16px; 
    border-radius: 12px; 
    overflow: hidden; 
    background: rgba(0,0,0,0.3); 
    transition: all 0.3s ease;
    box-shadow: 0 2px 12px rgba(0,0,0,0.2);
}
.rc-section-bad { 
    border: 1px solid rgba(239,68,68,0.25); 
    border-left: 4px solid #ef4444;
}
.rc-section-bad:hover { 
    border-color: rgba(239,68,68,0.4); 
    box-shadow: 0 4px 20px rgba(239,68,68,0.15);
}
.rc-section-good { 
    border: 1px solid rgba(34,197,94,0.25); 
    border-left: 4px solid #22c55e;
}
.rc-section-good:hover { 
    border-color: rgba(34,197,94,0.4); 
    box-shadow: 0 4px 20px rgba(34,197,94,0.12);
}

/* Header - beautiful */
.rc-header { 
    padding: 16px 20px; 
    cursor: pointer; 
    display: flex; 
    justify-content: space-between; 
    align-items: center; 
    user-select: none; 
    transition: all 0.25s ease;
    background: linear-gradient(135deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
}
.rc-section-bad .rc-header:hover { background: linear-gradient(135deg, rgba(239,68,68,0.08), rgba(239,68,68,0.03)); }
.rc-section-good .rc-header:hover { background: linear-gradient(135deg, rgba(34,197,94,0.08), rgba(34,197,94,0.03)); }
.rc-header-left { display: flex; align-items: center; gap: 14px; }

/* Icon - beautiful red/green */
.rc-icon { 
    width: 42px; height: 42px; 
    border-radius: 10px; 
    display: flex; align-items: center; justify-content: center; 
    font-size: 20px; flex-shrink: 0;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    position: relative;
}
.rc-icon-bad { 
    background: linear-gradient(135deg, #ef4444, #dc2626); 
    border: 1px solid rgba(239,68,68,0.5);
    box-shadow: 0 4px 12px rgba(239,68,68,0.3), inset 0 1px 0 rgba(255,255,255,0.2);
    color: white;
}
.rc-icon-bad::after {
    content: '';
    position: absolute;
    inset: -1px;
    border-radius: 10px;
    background: linear-gradient(135deg, rgba(255,255,255,0.2), transparent);
    pointer-events: none;
}
.rc-icon-good { 
    background: linear-gradient(135deg, #22c55e, #16a34a); 
    border: 1px solid rgba(34,197,94,0.5);
    box-shadow: 0 4px 12px rgba(34,197,94,0.3), inset 0 1px 0 rgba(255,255,255,0.2);
    color: white;
}
.rc-icon-good::after {
    content: '';
    position: absolute;
    inset: -1px;
    border-radius: 10px;
    background: linear-gradient(135deg, rgba(255,255,255,0.2), transparent);
    pointer-events: none;
}

.rc-title { font-size: 15px; font-weight: 700; color: #f0f0f5; letter-spacing: -0.2px; }
.rc-section-bad .rc-title { color: #fecaca; }
.rc-section-good .rc-title { color: #bbf7d0; }
.rc-subtitle { font-size: 11.5px; opacity: 0.65; margin-top: 3px; color: #a0a0b0; font-weight: 400; }
.rc-arrow { 
    transition: all 0.3s cubic-bezier(0.4,0,0.2,1); 
    opacity: 0.6; 
    font-size: 14px; 
    width: 28px; height: 28px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 6px;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
}
.rc-section.open .rc-arrow { transform: rotate(180deg); background: rgba(255,255,255,0.08); opacity: 1; }
.rc-content { max-height: 0; overflow: hidden; transition: max-height 0.5s cubic-bezier(0.4,0,0.2,1), padding 0.4s ease; padding: 0 20px; }
.rc-section.open .rc-content { max-height: 4000px; padding: 0 20px 20px; }

/* Explanation - distinct colors */
.rc-explain { 
    font-size: 13.5px; 
    line-height: 1.75; 
    margin: 10px 0; 
    padding: 12px 14px;
    border-radius: 8px;
    border-left: 3px solid transparent;
}
.rc-section-bad .rc-explain {
    color: #e0c0c0;
    background: rgba(239,68,68,0.06);
    border-left-color: rgba(239,68,68,0.3);
}
.rc-section-bad .rc-explain strong { color: #fecaca; font-weight: 700; }
.rc-section-good .rc-explain {
    color: #c0e0c8;
    background: rgba(34,197,94,0.06);
    border-left-color: rgba(34,197,94,0.3);
}
.rc-section-good .rc-explain strong { color: #bbf7d0; font-weight: 700; }

/* Code box - beautiful */
.rc-code-wrapper { 
    margin: 14px 0; 
    border-radius: 10px; 
    overflow: hidden; 
    background: #0a0a0f;
    border: 1px solid rgba(255,255,255,0.08);
    box-shadow: 0 4px 16px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05);
}
.rc-code-header {
    padding: 10px 14px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
.rc-code-header-bad {
    background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(239,68,68,0.08));
    color: #f87171;
    border-bottom-color: rgba(239,68,68,0.15);
}
.rc-code-header-good {
    background: linear-gradient(135deg, rgba(34,197,94,0.15), rgba(34,197,94,0.08));
    color: #4ade80;
    border-bottom-color: rgba(34,197,94,0.15);
}
.rc-code-dots { display: flex; gap: 5px; }
.rc-code-dot { width: 8px; height: 8px; border-radius: 50%; }
.rc-code-dot.red { background: #ef4444; }
.rc-code-dot.yellow { background: #eab308; }
.rc-code-dot.green { background: #22c55e; }
.rc-code {
    background: #0d0d12;
    padding: 16px;
    margin: 0;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    font-size: 12.5px;
    line-height: 1.7;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    color: #c0c0d0;
    max-height: 400px;
    overflow-y: auto;
}

/* Badges */
.rc-badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-right: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }
.rc-badge-bad { background: linear-gradient(135deg, rgba(239,68,68,0.2), rgba(220,38,38,0.15)); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
.rc-badge-good { background: linear-gradient(135deg, rgba(34,197,94,0.2), rgba(22,163,74,0.15)); color: #86efac; border: 1px solid rgba(34,197,94,0.3); }
.rc-badge-info { background: linear-gradient(135deg, rgba(59,130,246,0.2), rgba(37,99,235,0.15)); color: #93c5fd; border: 1px solid rgba(59,130,246,0.3); }

/* Impact box - beautiful */
.rc-impact { 
    background: linear-gradient(135deg, rgba(59,130,246,0.08), rgba(37,99,235,0.05)); 
    border: 1px solid rgba(59,130,246,0.2); 
    border-left: 4px solid #3b82f6;
    border-radius: 10px; 
    padding: 14px 16px; 
    margin-top: 16px; 
    font-size: 13px; 
    line-height: 1.65; 
    color: #a0b8d8;
    box-shadow: 0 2px 12px rgba(59,130,246,0.08);
}
.rc-impact strong { color: #93c5fd; }

/* Steps */
.rc-steps { margin-top: 14px; }
.rc-step { 
    font-size: 13px; 
    line-height: 1.6; 
    margin: 8px 0; 
    padding: 10px 12px;
    background: rgba(34,197,94,0.05);
    border: 1px solid rgba(34,197,94,0.1);
    border-left: 3px solid #22c55e;
    border-radius: 6px;
    color: #b0d0b8;
}
.rc-step strong { color: #86efac; }

/* VSCode-like syntax highlighting - beautiful colorful code */
.rc-code .token-comment { color: #6A9955; font-style: italic; }
.rc-code .token-string { color: #CE9178; }
.rc-code .token-keyword { color: #C586C0; font-weight: 600; }
.rc-code .token-variable { color: #9CDCFE; }
.rc-code .token-function { color: #DCDCAA; }
.rc-code .token-tag { color: #569CD6; font-weight: 600; }
.rc-code .token-number { color: #B5CEA8; }
.rc-code .token-operator { color: #D4D4D4; }
.rc-code .token-builtin { color: #4EC9B0; }
.rc-code .token-attr { color: #9CDCFE; }
</style>

<style>
/* Extra spacing for root cause to not mix with top */
.root-cause-box { margin-top: 8px; padding-top: 28px !important; }
.root-cause-box h2 { margin-bottom: 20px !important; padding-bottom: 12px; border-bottom: 1px solid rgba(239,68,68,0.15); }
</style>

<script>
// VSCode-like syntax highlighter
function highlightCodeElement(el) {
    if (el.dataset.highlighted) return;
    let code = el.textContent;
    const placeholders = [];
    let idx = 0;
    function save(str, type) {
        const key = `__PH_${idx}__`;
        placeholders.push({key, str, type});
        idx++;
        return key;
    }
    // Comments // and #
    code = code.replace(/(\/\/.*$|#.*$)/gm, m => save(m, 'comment'));
    // Multi-line /* */
    code = code.replace(/\/\*[\s\S]*?\*\//g, m => save(m, 'comment'));
    // Strings
    code = code.replace(/(['"])(?:\\.|(?!\1)[^\\])*\1/g, m => save(m, 'string'));
    // Keywords
    code = code.replace(/\b(if|else|elseif|die|echo|return|function|class|new|for|foreach|while|as|in_array|strtolower|strtoupper|pathinfo|move_uploaded_file|finfo_open|finfo_file|getimagesize|basename|bin2hex|random_bytes|chmod|strpos|stripos|preg_match|htmlspecialchars|implode|explode|array|true|false|null|isset|empty|continue|break)\b/g, '<span class="token-keyword">$1</span>');
    // Variables
    code = code.replace(/(\$[a-zA-Z_][a-zA-Z0-9_]*)/g, '<span class="token-variable">$1</span>');
    // Functions
    code = code.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?=\()/g, '<span class="token-function">$1</span>');
    // Numbers
    code = code.replace(/\b(\d+)\b/g, '<span class="token-number">$1</span>');
    // Tags
    code = code.replace(/(&lt;\?php|\?&gt;)/g, '<span class="token-tag">$1</span>');
    // Restore
    placeholders.forEach(ph => {
        let cls = ph.type === 'comment' ? 'token-comment' : 'token-string';
        let esc = ph.str.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        let colored = `<span class="${cls}">${esc}</span>`;
        code = code.split(ph.key).join(colored);
    });
    el.innerHTML = code;
    el.dataset.highlighted = '1';
}
function highlightAllCode() {
    document.querySelectorAll('.rc-code').forEach(el => highlightCodeElement(el));
}
document.addEventListener('DOMContentLoaded', highlightAllCode);
document.addEventListener('click', function(e) {
    if (e.target.closest('.rc-header') || e.target.closest('#root-toggle')) {
        setTimeout(highlightAllCode, 80);
    }
});
</script>

<div class="hint-box root-cause-box" id="root-box" hidden>
    <h2>🔍 Root Cause - Why This Bug Happens</h2>
<?php if (!empty($labRootCause)): ?>
    <div style="height: 12px;"></div>

    <!-- Bad Section - RED beautiful -->
    <div class="rc-section rc-section-bad" id="rc-bad-section">
        <div class="rc-header" onclick="document.getElementById('rc-bad-section').classList.toggle('open')">
            <div class="rc-header-left">
                <div class="rc-icon rc-icon-bad">⚠️</div>
                <div>
                    <div class="rc-title">What programmer did wrong</div>
                    <div class="rc-subtitle">Click to expand - vulnerable code & mistake</div>
                </div>
            </div>
            <div class="rc-arrow">▼</div>
        </div>
        <div class="rc-content">
            <?php if (!empty($labRootCause['bad']['explanation'])): ?>
                <?php foreach ((array) $labRootCause['bad']['explanation'] as $p): ?>
                    <p class="rc-explain"><?= $p ?></p>
                <?php endforeach; ?>
            <?php endif; ?>
            <?php if (!empty($labRootCause['bad']['code'])): ?>
                <div class="rc-code-wrapper">
                    <div class="rc-code-header rc-code-header-bad">
                        <div class="rc-code-dots"><div class="rc-code-dot red"></div><div class="rc-code-dot yellow"></div><div class="rc-code-dot green"></div></div>
                        <span>❌ Vulnerable Code - Bad Example</span>
                    </div>
                    <pre class="rc-code"><?= htmlspecialchars(implode("\n", (array) $labRootCause['bad']['code']), ENT_QUOTES) ?></pre>
                </div>
            <?php endif; ?>
            <?php if (!empty($labRootCause['bad']['impact'])): ?>
                <div class="rc-impact"><strong>🎯 Impact:</strong> <?= htmlspecialchars($labRootCause['bad']['impact'], ENT_QUOTES) ?></div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Good Section - GREEN beautiful -->
    <div class="rc-section rc-section-good" id="rc-good-section">
        <div class="rc-header" onclick="document.getElementById('rc-good-section').classList.toggle('open')">
            <div class="rc-header-left">
                <div class="rc-icon rc-icon-good">✓</div>
                <div>
                    <div class="rc-title">How to fix - Secure code</div>
                    <div class="rc-subtitle">Click to expand - secure code & fix steps</div>
                </div>
            </div>
            <div class="rc-arrow">▼</div>
        </div>
        <div class="rc-content">
            <?php if (!empty($labRootCause['good']['explanation'])): ?>
                <?php foreach ((array) $labRootCause['good']['explanation'] as $p): ?>
                    <p class="rc-explain"><?= $p ?></p>
                <?php endforeach; ?>
            <?php endif; ?>
            <?php if (!empty($labRootCause['good']['code'])): ?>
                <div class="rc-code-wrapper">
                    <div class="rc-code-header rc-code-header-good">
                        <div class="rc-code-dots"><div class="rc-code-dot red"></div><div class="rc-code-dot yellow"></div><div class="rc-code-dot green"></div></div>
                        <span>✅ Secure Code - Good Example</span>
                    </div>
                    <pre class="rc-code"><?= htmlspecialchars(implode("\n", (array) $labRootCause['good']['code']), ENT_QUOTES) ?></pre>
                </div>
            <?php endif; ?>
            <?php if (!empty($labRootCause['good']['steps'])): ?>
                <div class="rc-steps">
                    <?php foreach ((array) $labRootCause['good']['steps'] as $s): ?>
                        <div class="rc-step">• <?= htmlspecialchars($s, ENT_QUOTES) ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

<?php else: ?>
    <p class="hint-empty">no root cause written for this scenario yet</p>
<?php endif; ?>
</div>

<script>
var drawers = [
        { btn: 'hint-toggle', box: 'hint-box' },
        { btn: 'desc-toggle', box: 'desc-box' },
        { btn: 'root-toggle', box: 'root-box' }
    ];
    function closeAll(except) {
        drawers.forEach(function (d) {
            var box = document.getElementById(d.box);
            var btn = document.getElementById(d.btn);
            if (!box || !btn || box === except) return;
            box.setAttribute('hidden', '');
            btn.setAttribute('aria-expanded', 'false');
        });
    }
    drawers.forEach(function (d) {
        var btn = document.getElementById(d.btn);
        var box = document.getElementById(d.box);
        if (!btn || !box) return;
        btn.addEventListener('click', function () {
            var willOpen = box.hasAttribute('hidden');
            closeAll(willOpen ? box : null);
            if (willOpen) { box.removeAttribute('hidden'); } else { box.setAttribute('hidden', ''); }
            btn.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
            if (willOpen) { box.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }
        });
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeAll(null);
    });
</script>
