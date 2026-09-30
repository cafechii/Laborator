// File Upload · menu interactions — cards search + filter + threat mindmap
(function () {
    'use strict';

    // ─── CARD CLICK DELEGATION ───
    document.addEventListener('click', function (e) {
        var card = e.target.closest('.lab-card');
        if (card && !e.target.closest('a')) {
            var btn = card.querySelector('a.launch-button');
            if (btn) {
                btn.click();
            }
        }
    });

    // ─── CARDS VIEW CONTROLS ───
    var search = document.getElementById('lab-search');
    var cards = Array.prototype.slice.call(document.querySelectorAll('.lab-card'));
    var noResults = document.getElementById('no-results');

    var toggle = document.getElementById('filter-toggle');
    var menu = document.getElementById('filter-menu');

    var activeDiff = 'all';
    var activeSev = 'all';

    function filterLabs() {
        var q = (search ? search.value : '').toLowerCase().trim();
        var visible = 0;
        cards.forEach(function (card) {
            var diffOk = activeDiff === 'all' || card.getAttribute('data-diff') === activeDiff;
            var sevOk = activeSev === 'all' || card.getAttribute('data-sev') === activeSev;
            var searchOk = q === '' || (card.getAttribute('data-search') || '').toLowerCase().indexOf(q) !== -1;
            var show = diffOk && sevOk && searchOk;
            card.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        if (noResults) noResults.hidden = visible !== 0;
    }

    if (search) {
        search.addEventListener('input', filterLabs);
    }

    if (toggle && menu) {
        toggle.addEventListener('click', function (e) {
            e.stopPropagation();
            var willOpen = menu.hasAttribute('hidden');
            if (willOpen) {
                menu.removeAttribute('hidden');
                toggle.setAttribute('aria-expanded', 'true');
            } else {
                menu.setAttribute('hidden', '');
                toggle.setAttribute('aria-expanded', 'false');
            }
        });

        document.addEventListener('click', function (e) {
            if (!menu.hasAttribute('hidden') && !menu.contains(e.target) && !toggle.contains(e.target)) {
                menu.setAttribute('hidden', '');
                toggle.setAttribute('aria-expanded', 'false');
            }
        });

        Array.prototype.forEach.call(menu.querySelectorAll('[data-diff]'), function (btn) {
            btn.addEventListener('click', function () {
                activeDiff = btn.getAttribute('data-diff');
                Array.prototype.forEach.call(menu.querySelectorAll('[data-diff]'), function (b) {
                    b.classList.toggle('active', b === btn);
                });
                filterLabs();
            });
        });

        Array.prototype.forEach.call(menu.querySelectorAll('[data-sev]'), function (btn) {
            btn.addEventListener('click', function () {
                activeSev = btn.getAttribute('data-sev');
                Array.prototype.forEach.call(menu.querySelectorAll('[data-sev]'), function (b) {
                    b.classList.toggle('active', b === btn);
                });
                filterLabs();
            });
        });
    }

    // Initial card filter run
    filterLabs();

    // ─── VIEW SWITCHER (CARDS VS MINDMAP) ───
    var tabCards = document.getElementById('tab-cards-view');
    var tabMindmap = document.getElementById('tab-mindmap-view');
    var cardsWrap = document.getElementById('cards-view-wrap');
    var mindmapWrap = document.getElementById('mindmap-view');

    function switchView(viewName) {
        if (viewName === 'mindmap') {
            if (tabCards) tabCards.classList.remove('active');
            if (tabMindmap) tabMindmap.classList.add('active');
            if (cardsWrap) cardsWrap.hidden = true;
            if (mindmapWrap) mindmapWrap.hidden = false;
        } else {
            if (tabCards) tabCards.classList.add('active');
            if (tabMindmap) tabMindmap.classList.remove('active');
            if (cardsWrap) cardsWrap.hidden = false;
            if (mindmapWrap) mindmapWrap.hidden = true;
        }
    }

    if (tabCards) {
        tabCards.addEventListener('click', function () { switchView('cards'); });
    }
    if (tabMindmap) {
        tabMindmap.addEventListener('click', function () { switchView('mindmap'); });
    }

    // ─── MINDMAP BRANCH FILTERING & SEARCH ───
    var mapSearch = document.getElementById('map-search');
    var mapNodes = Array.prototype.slice.call(document.querySelectorAll('.tree-node'));
    var treeBranches = Array.prototype.slice.call(document.querySelectorAll('.tree-branch'));
    var branchPills = Array.prototype.slice.call(document.querySelectorAll('.branch-pill'));
    var activeBranch = 'all';

    function filterMindmap() {
        var q = (mapSearch ? mapSearch.value : '').toLowerCase().trim();

        // Branch visibility filter
        treeBranches.forEach(function (branch) {
            var branchId = branch.getAttribute('data-branch');
            var matches = activeBranch === 'all' || activeBranch === branchId;
            branch.style.display = matches ? '' : 'none';
        });

        // Search highlight
        mapNodes.forEach(function (node) {
            var text = (node.getAttribute('data-search') || '').toLowerCase();
            var matches = q === '' || text.indexOf(q) !== -1;
            if (q !== '') {
                node.style.opacity = matches ? '1' : '0.2';
                node.style.transform = matches ? 'scale(1.02)' : 'scale(0.97)';
                if (matches) {
                    node.classList.add('search-highlight');
                } else {
                    node.classList.remove('search-highlight');
                }
            } else {
                node.style.opacity = '';
                node.style.transform = '';
                node.classList.remove('search-highlight');
            }
        });
    }

    if (mapSearch) {
        mapSearch.addEventListener('input', filterMindmap);
    }

    branchPills.forEach(function (pill) {
        pill.addEventListener('click', function () {
            activeBranch = pill.getAttribute('data-branch');
            branchPills.forEach(function (p) {
                p.classList.toggle('active', p === pill);
            });
            filterMindmap();
        });
    });

    // ─── MINDMAP ZOOM CONTROLS ───
    var canvas = document.getElementById('mindmap-canvas');
    var btnZoomIn = document.getElementById('map-zoom-in');
    var btnZoomOut = document.getElementById('map-zoom-out');
    var btnZoomReset = document.getElementById('map-zoom-reset');
    var currentZoom = 1.0;

    function applyZoom(z) {
        currentZoom = Math.min(Math.max(0.65, z), 1.4);
        if (canvas) {
            canvas.style.transform = 'scale(' + currentZoom + ')';
        }
    }

    if (btnZoomIn) {
        btnZoomIn.addEventListener('click', function () { applyZoom(currentZoom + 0.1); });
    }
    if (btnZoomOut) {
        btnZoomOut.addEventListener('click', function () { applyZoom(currentZoom - 0.1); });
    }
    if (btnZoomReset) {
        btnZoomReset.addEventListener('click', function () { applyZoom(1.0); });
    }

})();
