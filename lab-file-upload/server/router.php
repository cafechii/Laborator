<?php
// File Upload · dev server router
//
// The sandbox executes scenario code, but uploaded artifacts are DATA —
// except in scenarios where "unrestricted upload -> RCE" is the INTENDED
// bug. Those scenario numbers are listed in $uploadRceAllowed below; in
// every other scenario a .php inside uploads/ is refused (403).

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Root -> menu
if ($uri === '/' || $uri === '') {
    header('Location: /menu/');
    exit;
}

// /menu without slash -> /menu/
if ($uri === '/menu') {
    header('Location: /menu/');
    exit;
}

// Redirect /Labs/... prefixes to root level
if (preg_match('#^/Labs(/.*)?$#', $uri, $m)) {
    $sub = $m[1] ?? '/';
    header('Location: ' . ($sub ?: '/menu/'));
    exit;
}

// Normalize single-digit scenario paths e.g. /scenario1/ -> /scenario01/
if (preg_match('#^/scenario([1-9])(/.*)?$#', $uri, $m)) {
    $sub = $m[2] ?? '/';
    header('Location: /scenario0' . $m[1] . $sub);
    exit;
}

// Ensure trailing slash for scenario directories e.g. /scenario01 -> /scenario01/
if (preg_match('#^/scenario\d+$#', $uri)) {
    header('Location: ' . $uri . '/');
    exit;
}

$paths = array_unique([$uri, rawurldecode($uri)]);

// Scenario numbers whose intended flaw ends in a PHP file inside uploads/.
// There the execution IS the lesson, so the dev router lets it run. Every
// other slot keeps uploads/ inert, which is what makes each lab one bug.
$uploadRceAllowed = [1, 3, 5, 8, 9, 11, 17, 19, 20, 21, 23, 30];

foreach ($paths as $p) {
    if (preg_match('#^/scenario(\d+)/uploads/.*\.php$#i', $p, $m)) {
        if (in_array((int) $m[1], $uploadRceAllowed, true)) {
            return false; // intended bug: let the uploaded .php execute
        }
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "execution blocked: uploads/ artifacts are served as data only";
        return true; // handled
    }
}

return false; // built-in server handles it normally
