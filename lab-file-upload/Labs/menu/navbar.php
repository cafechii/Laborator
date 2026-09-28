<!-- Background layers -->
<div class="background-grid" aria-hidden="true"></div>

<!-- ═══════ Topbar / navbar ═══════ -->
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
</header>

<!-- ═══════ Bench bar · hint + back, under the topbar ═══════ -->
<div class="bench-bar">
    <div class="bench-bar-inner">
        <div class="bench-bar-left">
            <button class="hint-button desc-button" type="button" id="desc-toggle"
                    aria-expanded="false" aria-controls="desc-box">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" aria-hidden="true">
                    <path d="M4 6h16M4 12h16M4 18h11" />
                </svg>
                Description
            </button>
            <button class="hint-button" type="button" id="hint-toggle"
                    aria-expanded="false" aria-controls="hint-box">
            <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M12 2a7 7 0 0 0-4 12.7.9.9 0 0 1 .3.6V17a2 2 0 0 0 2 2h3.4a2 2 0 0 0 2-2v-1.7a.9.9 0 0 1 .3-.6A7 7 0 0 0 12 2Zm-2.6 19h5.2a1.3 1.3 0 0 1-1.3 1h-2.6a1.3 1.3 0 0 1-1.3-1Z"/>
            </svg>
            Hint
            </button>
        </div>
        <a class="primary-button" href="/menu/">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                 stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M19 12H5m7-7-7 7 7 7" />
            </svg>
            Back to menu
        </a>
    </div>
</div>

<!-- ═══════ Description drawer · filled by $labDescription on the page ═══════ -->
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

<!-- ═══════ Hint drawer (content per scenario, see below) ═══════ -->
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

<script>
// topbar hint toggle (shared by every lab page through navbar.php)
var drawers = [
        { btn: 'hint-toggle', box: 'hint-box' },
        { btn: 'desc-toggle', box: 'desc-box' }
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
