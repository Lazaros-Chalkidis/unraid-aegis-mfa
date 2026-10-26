<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// every aegis_*() call must have a definition in its own file's require chain. run: php tests/requires.test.php
// catches the exact bug class that shipped webauthn.login.*.php calling aegis_mfa_csrf_check() while only requiring AegisMfaGate.php, which never defines it
// built on token_get_all(), not regex: a couple of source files mention aegis_*() names inside comments or string literals, which a tokenizer tells apart and regex cannot

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

$srcRoot = __DIR__ . '/../source';

function amfa_read_php_source(string $path): string {
    $code = file_get_contents($path);
    // *.page files carry a non-PHP Menu/Title/Icon header before a lone "---" line
    $sep = strpos($code, "\n---\n");
    return $sep !== false ? substr($code, $sep + 5) : $code;
}

function amfa_tokens(string $path): array {
    return token_get_all(amfa_read_php_source($path));
}

// skips whitespace/comments starting at $i, returns the index of the next "real" token
function amfa_next_real(array $tokens, int $i): int {
    $n = count($tokens);
    while ($i < $n) {
        if (is_array($tokens[$i]) && in_array($tokens[$i][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            $i++;
            continue;
        }
        return $i;
    }
    return $i;
}

// every top-level `function name(` declaration
function amfa_defined_functions(string $path): array {
    $tokens = amfa_tokens($path);
    $out = [];
    foreach ($tokens as $i => $tok) {
        if (!is_array($tok) || $tok[0] !== T_FUNCTION) continue;
        $j = amfa_next_real($tokens, $i + 1);
        if (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) $out[] = $tokens[$j][1];
    }
    return $out;
}

// every aegis_*( identifier used in call position (a T_STRING immediately followed by '(') - excludes comments and string literals, which the tokenizer already classifies separately
function amfa_called_aegis_functions(string $path): array {
    $tokens = amfa_tokens($path);
    $out = [];
    foreach ($tokens as $i => $tok) {
        if (!is_array($tok) || $tok[0] !== T_STRING) continue;
        if (strpos($tok[1], 'aegis_') !== 0) continue;
        $j = amfa_next_real($tokens, $i + 1);
        if (isset($tokens[$j]) && $tokens[$j] === '(') $out[] = $tok[1];
    }
    return array_unique($out);
}

// basenames of every require_once target, whichever of this codebase's two styles is used:
// require_once __DIR__ . '/X.php';  or  require_once '/usr/local/emhttp/.../X.php'
function amfa_required_basenames(string $path): array {
    $tokens = amfa_tokens($path);
    $out = [];
    $n = count($tokens);
    foreach ($tokens as $i => $tok) {
        if (!is_array($tok) || $tok[0] !== T_REQUIRE_ONCE) continue;
        $buf = '';
        for ($j = $i + 1; $j < $n && $tokens[$j] !== ';'; $j++) {
            if (is_array($tokens[$j]) && $tokens[$j][0] === T_CONSTANT_ENCAPSED_STRING) {
                $buf .= trim($tokens[$j][1], "'\"");
            }
        }
        if ($buf !== '') $out[] = basename($buf);
    }
    return $out;
}

// one map, basename -> real path, covering both require targets (source/include/*.php) and top-level entry points (challenge.view.php, AegisMfa.page)
// resolution below looks everything up through this map, so an entry point's own requires get walked exactly like a library file's would
$allFiles = [];
foreach (glob($srcRoot . '/include/*.php') as $f) {
    $allFiles[basename($f)] = $f;
}
foreach ([$srcRoot . '/challenge.view.php', $srcRoot . '/AegisMfa.page'] as $f) {
    $allFiles[basename($f)] = $f;
}

function amfa_resolve_closure(string $basename, array $allFiles, array &$seen = []): array {
    if (isset($seen[$basename]) || !isset($allFiles[$basename])) return [];
    $seen[$basename] = true;
    $out = [$basename];
    foreach (amfa_required_basenames($allFiles[$basename]) as $req) {
        $out = array_merge($out, amfa_resolve_closure($req, $allFiles, $seen));
    }
    return $out;
}

function amfa_check_file(string $file, array $allFiles): void {
    $base = basename($file);
    $closure = amfa_resolve_closure($base, $allFiles);
    if (!in_array($base, $closure, true)) $closure[] = $base; // always check its own definitions too

    $defined = [];
    foreach (array_unique($closure) as $cb) {
        $defined = array_merge($defined, amfa_defined_functions($allFiles[$cb] ?? $file));
    }
    $defined = array_flip($defined);

    foreach (amfa_called_aegis_functions($file) as $fn) {
        t("$base calls $fn() with something in its require chain defining it", isset($defined[$fn]));
    }
}

// every file in the map, library and entry-point alike, checked against its own chain
foreach ($allFiles as $file) {
    amfa_check_file($file, $allFiles);
}

echo "\nrequires.test.php: {$pass} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);
