// File Upload · Scenario 2 — the only validation this lab has, and it runs in
// the browser. The server does not validate the file. A request modified in
// Burp or sent directly never has to pass this script.
(function () {
    'use strict';

    var ALLOWED_TYPES = ['image/png'];
    var ALLOWED_LABEL = 'PNG image';

    var form = document.getElementById('uploadForm');
    var input = document.getElementById('fileToUpload');
    var errorMsg = document.getElementById('errorMsg');
    var uploadText = document.getElementById('uploadtext');
    var errorTimer = null;

    // Do not silently fail if the page is embedded or partially cached.
    if (!form || !input || !errorMsg || !uploadText) return;

    function setVisible(element, visible) {
        if (visible) {
            element.removeAttribute('hidden');
        } else {
            element.setAttribute('hidden', '');
        }
    }

    function isAllowed(file) {
        return !!file && ALLOWED_TYPES.indexOf(file.type) !== -1;
    }

    function showError(text) {
        errorMsg.textContent = text;
        setVisible(errorMsg, true);
        setVisible(uploadText, false);
        if (errorTimer) clearTimeout(errorTimer);
        errorTimer = setTimeout(function () {
            setVisible(errorMsg, false);
        }, 5000);
    }

    input.addEventListener('change', function () {
        var file = input.files[0];

        setVisible(errorMsg, false);
        setVisible(uploadText, false);
        if (!file) return;

        if (!isAllowed(file)) {
            input.value = '';
            showError('Invalid File Type — only ' + ALLOWED_LABEL + ' is accepted.');
            return;
        }

        uploadText.textContent = 'Chosen File: ' + file.name;
        setVisible(uploadText, true);
    });

    form.addEventListener('submit', function (event) {
        var file = input.files[0];

        if (!isAllowed(file)) {
            event.preventDefault();
            showError('Invalid File Type — choose a real PNG, or intercept this request and change it in Burp.');
        }
    });
})();
