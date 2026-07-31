<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// QR matrices, cross-checked by qr_decode.py. run: php tests/qr.test.php

require __DIR__ . '/../source/include/AegisMfaQr.php';
require __DIR__ . '/../source/include/AegisMfaTotp.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

$hello = aegis_qr_encode('HELLO');
t('matrix is array', is_array($hello) && count($hello) > 0);
t('matrix square', count($hello) === count($hello[0]));
t('matrix size 21 (v1)', count($hello) === 21);
t('cells are 0/1', $hello[0][0] === 1 && in_array($hello[0][8], [0, 1], true));

$tl_ok = $hello[0][0] === 1 && $hello[0][6] === 1 && $hello[6][0] === 1
      && $hello[1][1] === 0 && $hello[2][2] === 1 && $hello[3][3] === 1;
t('finder pattern top-left', $tl_ok);

$uri = aegis_totp_uri(aegis_totp_generate_secret(), 'root@raptor1', 'Aegis MFA');
$m = aegis_qr_encode($uri);
t('otpauth matrix square', count($m) === count($m[0]));
t('otpauth version >= 7', count($m) >= 45);

$long = aegis_totp_uri(aegis_totp_generate_secret(), 'a.very.long.username@raptor-homelab-01', 'Aegis MFA');
$ml = aegis_qr_encode($long);
t('long uri encodes', count($ml) >= count($m));

$svg = aegis_qr_svg($hello, 6, 4);
t('svg starts tag', str_starts_with($svg, '<svg'));
t('svg ends tag', str_ends_with($svg, '</svg>'));
t('svg has viewBox', strpos($svg, 'viewBox="0 0') !== false);
t('svg has white bg', strpos($svg, 'fill="#ffffff"') !== false);
t('svg has black path', strpos($svg, 'fill="#000000"') !== false);
$expectedDim = (21 + 2 * 4) * 6;
t('svg dimension correct', strpos($svg, 'width="' . $expectedDim . '"') !== false);

t('encode deterministic', aegis_qr_encode('HELLO') === $hello);

$dump = [
    'hello'   => ['data' => 'HELLO', 'matrix' => array_map(fn($r) => implode('', $r), $hello)],
    'url'     => ['data' => 'https://chalkidis.net',
                  'matrix' => array_map(fn($r) => implode('', $r), aegis_qr_encode('https://chalkidis.net'))],
    'otpauth' => ['data' => $uri, 'matrix' => array_map(fn($r) => implode('', $r), $m)],
    'long'    => ['data' => $long, 'matrix' => array_map(fn($r) => implode('', $r), $ml)],
];
@file_put_contents(sys_get_temp_dir() . '/aegis_qr_dump.json', json_encode($dump));

// the vendored library ends in E_USER_ERROR past its capacity table, which no try/catch holds
t('over capacity returns empty', aegis_qr_encode(str_repeat('A', aegis_qr_max_bytes() + 1)) === []);
t('at capacity still encodes',   count(aegis_qr_encode(str_repeat('A', aegis_qr_max_bytes()))) > 0);
t('empty input returns empty',   aegis_qr_encode('') === []);
t('empty matrix gives no svg',   aegis_qr_svg([]) === '');
t('null bytes survive',          count(aegis_qr_encode("a\x00b")) === 21);
t('invalid utf8 survives',       count(aegis_qr_encode("\xC3\x28\xA0")) === 21);
t('high bytes survive',          count(aegis_qr_encode(implode('', array_map('chr', range(128, 255))))) > 0);

echo "\nqr.test.php: {$pass} passed, {$fail} failed\n";
echo "(matrices dumped to " . sys_get_temp_dir() . "/aegis_qr_dump.json for decoder cross-check)\n";
exit($fail === 0 ? 0 : 1);
