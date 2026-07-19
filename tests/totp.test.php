<?php
/*
 * Aegis MFA - TOTP test suite
 * run: php tests/totp.test.php
 * exit 0 on full pass, 1 on any failure
 */

require __DIR__ . '/../source/include/AegisMfaTotp.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

// base32, RFC 4648
// the shared RFC 4226/6238 test secret and its known base32 form
$ref = '12345678901234567890';
$b32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

t('b32 encode ref',    aegis_totp_b32encode($ref) === $b32);
t('b32 decode ref',    aegis_totp_b32decode($b32) === $ref);
t('b32 lowercase',     aegis_totp_b32decode(strtolower($b32)) === $ref);
t('b32 grouped',       aegis_totp_b32decode('GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ') === $ref);
t('b32 padding',       aegis_totp_b32decode($b32 . '===') === $ref);
t('b32 invalid char',  aegis_totp_b32decode('GEZ1GNBV') === false);
t('b32 invalid char 2', aegis_totp_b32decode('GEZ$GNBV') === false);
t('b32 empty',         aegis_totp_b32decode('') === false);
t('b32 only padding',  aegis_totp_b32decode('===') === false);

for ($i = 0; $i < 20; $i++) {
    $raw = random_bytes(random_int(1, 40));
    t("b32 roundtrip len " . strlen($raw), aegis_totp_b32decode(aegis_totp_b32encode($raw)) === $raw);
}

// HOTP, RFC 4226 appendix D vectors
$hotp = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
foreach ($hotp as $c => $want) {
    t("hotp counter $c", aegis_totp_hotp($ref, $c) === $want);
}

// TOTP, RFC 6238 appendix B vectors (SHA1, 8 digits)
$totp8 = [
    59          => '94287082',
    1111111109  => '07081804',
    1111111111  => '14050471',
    1234567890  => '89005924',
    2000000000  => '69279037',
    20000000000 => '65353130',
];
foreach ($totp8 as $time => $want) {
    t("totp8 T=$time", aegis_totp_hotp($ref, intdiv($time, 30), 8) === $want);
}

// verify + window behaviour (injected clock)
$b32ref = aegis_totp_b32encode($ref);
$now    = 1111111111;            // step 37037037
$cur    = aegis_totp_hotp($ref, 37037037);
$prev   = aegis_totp_hotp($ref, 37037036);
$next   = aegis_totp_hotp($ref, 37037038);
$old2   = aegis_totp_hotp($ref, 37037035);
$wrong  = ($cur === '000000') ? '000001' : '000000';

t('verify current',          aegis_totp_verify($b32ref, $cur,  1, 30, $now) === true);
t('verify prev in window',   aegis_totp_verify($b32ref, $prev, 1, 30, $now) === true);
t('verify next in window',   aegis_totp_verify($b32ref, $next, 1, 30, $now) === true);
t('verify -2 outside w1',    aegis_totp_verify($b32ref, $old2, 1, 30, $now) === false);
t('verify -2 inside w2',     aegis_totp_verify($b32ref, $old2, 2, 30, $now) === true);
t('verify wrong code',       aegis_totp_verify($b32ref, $wrong, 1, 30, $now) === false);
t('verify spaced input',     aegis_totp_verify($b32ref, substr($cur, 0, 3) . ' ' . substr($cur, 3), 1, 30, $now) === true);
t('verify 5 digits',         aegis_totp_verify($b32ref, '12345', 1, 30, $now) === false);
t('verify 7 digits',         aegis_totp_verify($b32ref, $cur . '1', 1, 30, $now) === false);
t('verify empty',            aegis_totp_verify($b32ref, '', 1, 30, $now) === false);
t('verify letters',          aegis_totp_verify($b32ref, 'abcdef', 1, 30, $now) === false);
t('verify bad secret',       aegis_totp_verify('GEZ1', $cur, 1, 30, $now) === false);
t('verify short secret',     aegis_totp_verify(aegis_totp_b32encode('short'), $cur, 1, 30, $now) === false);

// verify_step returns the matched step for replay tracking
t('step exact',  aegis_totp_verify_step($b32ref, $cur,   1, 30, $now) === 37037037);
t('step prev',   aegis_totp_verify_step($b32ref, $prev,  1, 30, $now) === 37037036);
t('step next',   aegis_totp_verify_step($b32ref, $next,  1, 30, $now) === 37037038);
t('step none',   aegis_totp_verify_step($b32ref, $wrong, 1, 30, $now) === false);

// secret generation
$s1 = aegis_totp_generate_secret();
$s2 = aegis_totp_generate_secret();
t('secret length 32',   strlen($s1) === 32);
t('secret alphabet',    preg_match('/^[A-Z2-7]{32}$/', $s1) === 1);
t('secret unique',      $s1 !== $s2);
t('secret decodes 20B', strlen(aegis_totp_b32decode($s1)) === 20);
t('secret custom len',  strlen(aegis_totp_generate_secret(16)) === 16);

// provisioning URI
$uri = aegis_totp_uri('ABC234DEF567', 'root@raptor1');
t('uri label',   str_starts_with($uri, 'otpauth://totp/Aegis%20MFA:root%40raptor1?'));
t('uri secret',  strpos($uri, 'secret=ABC234DEF567') !== false);
t('uri issuer',  strpos($uri, 'issuer=Aegis%20MFA') !== false);
t('uri sha1',    strpos($uri, 'algorithm=SHA1') !== false);
t('uri digits',  strpos($uri, 'digits=6') !== false);
t('uri period',  strpos($uri, 'period=30') !== false);

// summary
echo "\ntotp.test.php: {$pass} passed, {$fail} failed\n";
exit($fail === 0 ? 0 : 1);
