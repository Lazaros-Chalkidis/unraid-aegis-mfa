<?php
/*
 * Aegis MFA - QR wrapper test suite
 * run: php tests/qr.test.php
 * exit 0 on full pass, 1 on any failure
 *
 * Structural checks here; scannability is cross-verified against a real
 * decoder in tests/qr_decode.py (run by the harness where cv2 is present).
 * This suite also dumps matrices to /tmp for that decoder step.
 */

require __DIR__ . '/../source/include/AegisMfaQr.php';
require __DIR__ . '/../source/include/AegisMfaTotp.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

// square boolean matrix of expected sizes
$hello = aegis_qr_encode('HELLO');
t('matrix is array', is_array($hello) && count($hello) > 0);
t('matrix square', count($hello) === count($hello[0]));
t('matrix size 21 (v1)', count($hello) === 21);
t('cells are 0/1', $hello[0][0] === 1 && in_array($hello[0][8], [0, 1], true));

// finder pattern present: top-left 7x7 has the classic dark border + core
$tl_ok = $hello[0][0] === 1 && $hello[0][6] === 1 && $hello[6][0] === 1
      && $hello[1][1] === 0 && $hello[2][2] === 1 && $hello[3][3] === 1;
t('finder pattern top-left', $tl_ok);

// otpauth URI (byte mode) picks a larger version and stays square
$uri = aegis_totp_uri(aegis_totp_generate_secret(), 'root@raptor1', 'Aegis MFA');
$m = aegis_qr_encode($uri);
t('otpauth matrix square', count($m) === count($m[0]));
t('otpauth version >= 7', count($m) >= 45);   // ~49x49 for our URI length

// a long account name still encodes without error
$long = aegis_totp_uri(aegis_totp_generate_secret(), 'a.very.long.username@raptor-homelab-01', 'Aegis MFA');
$ml = aegis_qr_encode($long);
t('long uri encodes', count($ml) >= count($m));

// SVG rendering
$svg = aegis_qr_svg($hello, 6, 4);
t('svg starts tag', str_starts_with($svg, '<svg'));
t('svg ends tag', str_ends_with($svg, '</svg>'));
t('svg has viewBox', strpos($svg, 'viewBox="0 0') !== false);
t('svg has white bg', strpos($svg, 'fill="#ffffff"') !== false);
t('svg has black path', strpos($svg, 'fill="#000000"') !== false);
$expectedDim = (21 + 2 * 4) * 6;   // (modules + 2*quiet) * scale
t('svg dimension correct', strpos($svg, 'width="' . $expectedDim . '"') !== false);

// same input is deterministic
t('encode deterministic', aegis_qr_encode('HELLO') === $hello);

// dump matrices for the external decoder cross-check
$dump = [
    'hello'   => ['data' => 'HELLO', 'matrix' => array_map(fn($r) => implode('', $r), $hello)],
    'url'     => ['data' => 'https://chalkidis.net',
                  'matrix' => array_map(fn($r) => implode('', $r), aegis_qr_encode('https://chalkidis.net'))],
    'otpauth' => ['data' => $uri, 'matrix' => array_map(fn($r) => implode('', $r), $m)],
    'long'    => ['data' => $long, 'matrix' => array_map(fn($r) => implode('', $r), $ml)],
];
@file_put_contents(sys_get_temp_dir() . '/aegis_qr_dump.json', json_encode($dump));

echo "\nqr.test.php: {$pass} passed, {$fail} failed\n";
echo "(matrices dumped to " . sys_get_temp_dir() . "/aegis_qr_dump.json for decoder cross-check)\n";
exit($fail === 0 ? 0 : 1);
