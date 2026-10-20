<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// CBOR decode, COSE/ES256 verification, full registration/assertion ceremonies. run: php tests/webauthn.test.php

$work = sys_get_temp_dir() . '/aegis-mfa-webauthn-' . getmypid();
@mkdir($work . '/flash', 0700, true);
define('AEGIS_MFA_FLASH_DIR', $work . '/flash');
define('AEGIS_MFA_STATE_DIR', $work . '/state');
ini_set('session.save_path', $work);

require __DIR__ . '/../source/include/AegisMfaWebauthn.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

// a tiny CBOR encoder, test-only: the plugin only ever decodes, this just builds fixtures

function cbor_head(int $major, int $n): string {
    if ($n < 24)     return chr(($major << 5) | $n);
    if ($n < 256)    return chr(($major << 5) | 24) . chr($n);
    if ($n < 65536)  return chr(($major << 5) | 25) . chr(($n >> 8) & 0xff) . chr($n & 0xff);
    return chr(($major << 5) | 26) . pack('N', $n);
}
function cbor_uint(int $n): string { return cbor_head(0, $n); }
function cbor_negint(int $n): string { return cbor_head(1, -1 - $n); } // $n is the negative number itself
function cbor_bytes(string $s): string { return cbor_head(2, strlen($s)) . $s; }
function cbor_text(string $s): string { return cbor_head(3, strlen($s)) . $s; }
function cbor_map_head(int $n): string { return cbor_head(5, $n); }

// RFC 8949 Appendix A vectors: known-good bytes, independent of anything WebAuthn-specific

t('cbor uint 0',     aegis_cbor_decode(hex2bin('00')) === 0);
t('cbor uint 10',    aegis_cbor_decode(hex2bin('0a')) === 10);
t('cbor uint 25',    aegis_cbor_decode(hex2bin('1819')) === 25);
t('cbor uint 100',   aegis_cbor_decode(hex2bin('1864')) === 100);
t('cbor uint 1000',  aegis_cbor_decode(hex2bin('1903e8')) === 1000);
t('cbor negint -1',  aegis_cbor_decode(hex2bin('20')) === -1);
t('cbor negint -10', aegis_cbor_decode(hex2bin('29')) === -10);
t('cbor negint -100',aegis_cbor_decode(hex2bin('3863')) === -100);
t('cbor bytes empty',aegis_cbor_decode(hex2bin('40')) === '');
t('cbor bytes 4',    aegis_cbor_decode(hex2bin('4401020304')) === "\x01\x02\x03\x04");
t('cbor text empty', aegis_cbor_decode(hex2bin('60')) === '');
t('cbor text a',     aegis_cbor_decode(hex2bin('6161')) === 'a');
t('cbor text IETF',  aegis_cbor_decode(hex2bin('6449455446')) === 'IETF');
t('cbor array empty',aegis_cbor_decode(hex2bin('80')) === []);
t('cbor array 123',  aegis_cbor_decode(hex2bin('83010203')) === [1, 2, 3]);
t('cbor map empty',  aegis_cbor_decode(hex2bin('a0')) === []);
t('cbor map 1234',   aegis_cbor_decode(hex2bin('a201020304')) === [1 => 2, 3 => 4]);
t('cbor false',      aegis_cbor_decode(hex2bin('f4')) === false);
t('cbor true',       aegis_cbor_decode(hex2bin('f5')) === true);
t('cbor null',       aegis_cbor_decode(hex2bin('f6')) === null);

t('cbor trailing bytes rejected', (function () {
    try { aegis_cbor_decode(hex2bin('0000')); return false; } catch (AegisWebauthnError $e) { return true; }
})());
t('cbor truncated rejected', (function () {
    try { aegis_cbor_decode(hex2bin('18')); return false; } catch (AegisWebauthnError $e) { return true; }
})());
t('cbor indefinite length rejected', (function () {
    try { aegis_cbor_decode(hex2bin('5f')); return false; } catch (AegisWebauthnError $e) { return true; }
})());

// COSE key extraction, restricted to EC2/P-256/ES256

$es256Cose = cbor_map_head(5)
    . cbor_uint(1)    . cbor_uint(2)               // kty(1) = EC2(2)
    . cbor_uint(3)    . cbor_negint(-7)             // alg(3) = ES256(-7)
    . cbor_negint(-1) . cbor_uint(1)                // crv(-1) = P-256(1)
    . cbor_negint(-2) . cbor_bytes(str_repeat("\x11", 32)) // x
    . cbor_negint(-3) . cbor_bytes(str_repeat("\x22", 32)); // y
$decodedCose = aegis_cbor_decode($es256Cose);
$ec = aegis_webauthn_cose_ec2_es256($decodedCose);
t('cose es256 accepted', $ec !== null);
t('cose es256 x',        $ec['x'] === str_repeat("\x11", 32));
t('cose es256 y',        $ec['y'] === str_repeat("\x22", 32));

$rs256Cose = cbor_map_head(4)
    . cbor_uint(1) . cbor_uint(3)      // kty = RSA(3)
    . cbor_uint(3) . cbor_negint(-257) // alg = RS256(-257)
    . cbor_negint(-1) . cbor_bytes(str_repeat("\x01", 32))
    . cbor_negint(-2) . cbor_bytes(str_repeat("\x01", 3));
t('cose non-ec2 rejected', aegis_webauthn_cose_ec2_es256(aegis_cbor_decode($rs256Cose)) === null);

$wrongCurve = cbor_map_head(5)
    . cbor_uint(1) . cbor_uint(2) . cbor_uint(3) . cbor_negint(-7)
    . cbor_negint(-1) . cbor_uint(2) // crv = P-384, not P-256
    . cbor_negint(-2) . cbor_bytes(str_repeat("\x11", 32))
    . cbor_negint(-3) . cbor_bytes(str_repeat("\x22", 32));
t('cose wrong curve rejected', aegis_webauthn_cose_ec2_es256(aegis_cbor_decode($wrongCurve)) === null);

// ES256 sign/verify round trip against a real P-256 keypair, padded to 32 bytes since openssl_pkey_get_details() can drop a leading zero byte

function p256_keypair(): array {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $details = openssl_pkey_get_details($key);
    $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
    $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);
    return [$key, $x, $y];
}

[$privKey, $kx, $ky] = p256_keypair();
$msg = 'aegis-mfa test payload';
openssl_sign($msg, $sig, $privKey, OPENSSL_ALGO_SHA256);

t('es256 verify accepts valid signature', aegis_webauthn_es256_verify($msg, $sig, $kx, $ky) === true);
t('es256 verify rejects tampered message', aegis_webauthn_es256_verify($msg . 'x', $sig, $kx, $ky) === false);
t('es256 verify rejects tampered signature', aegis_webauthn_es256_verify($msg, $sig . "\x00", $kx, $ky) === false);
[, $otherX, $otherY] = p256_keypair();
t('es256 verify rejects wrong key', aegis_webauthn_es256_verify($msg, $sig, $otherX, $otherY) === false);
t('es256 verify rejects short coordinates', aegis_webauthn_es256_verify($msg, $sig, 'short', $ky) === false);

// authData parsing

function build_auth_data(string $rpIdHash, int $flags, int $signCount, ?string $coseKey = null, ?string $credId = null): string {
    $out = $rpIdHash . chr($flags) . pack('N', $signCount);
    if ($coseKey !== null) {
        $credId = $credId ?? random_bytes(16);
        $out .= str_repeat("\x00", 16) . pack('n', strlen($credId)) . $credId . $coseKey;
    }
    return $out;
}

$rpId = 'test.example';
$rpIdHash = hash('sha256', $rpId, true);
$credId = random_bytes(16);
$authDataReg = build_auth_data($rpIdHash, 0x41, 0, $es256Cose, $credId); // UP|AT
$parsed = aegis_webauthn_parse_auth_data($authDataReg);
t('authData rp id hash', $parsed['rp_id_hash'] === $rpIdHash);
t('authData up flag', $parsed['up'] === true);
t('authData uv flag', $parsed['uv'] === false);
t('authData at flag', $parsed['at'] === true);
t('authData cred id', $parsed['cred_id'] === $credId);
t('authData cose key present', is_array($parsed['cose_key']));

t('authData too short rejected', (function () {
    try { aegis_webauthn_parse_auth_data('short'); return false; } catch (AegisWebauthnError $e) { return true; }
})());

// full registration verification (webauthn.create)

function b64u($s) { return aegis_webauthn_b64url_encode($s); }

$regChallenge = b64u(random_bytes(32));
$origin = 'https://' . $rpId;
$clientDataReg = json_encode(['type' => 'webauthn.create', 'challenge' => $regChallenge, 'origin' => $origin]);
$attObj = cbor_map_head(3)
    . cbor_text('fmt')      . cbor_text('none')
    . cbor_text('attStmt')  . cbor_map_head(0)
    . cbor_text('authData') . cbor_bytes($authDataReg);

$regCred = [
    'id'   => b64u($credId),
    'type' => 'public-key',
    'response' => [
        'clientDataJSON'    => b64u($clientDataReg),
        'attestationObject' => b64u($attObj),
    ],
];

$reg = aegis_webauthn_verify_registration($regCred, $regChallenge, $origin, $rpId);
t('registration ok', ($reg['ok'] ?? false) === true);
t('registration credential id', ($reg['credential_id'] ?? null) === $credId);
t('registration public key x', base64_decode((string)($reg['public_key']['x'] ?? '')) === str_repeat("\x11", 32));
t('registration sign count', ($reg['sign_count'] ?? null) === 0);

$regWrongChallenge = aegis_webauthn_verify_registration($regCred, b64u(random_bytes(32)), $origin, $rpId);
t('registration wrong challenge rejected', ($regWrongChallenge['ok'] ?? true) === false);

$regWrongOrigin = aegis_webauthn_verify_registration($regCred, $regChallenge, 'https://evil.example', $rpId);
t('registration wrong origin rejected', ($regWrongOrigin['ok'] ?? true) === false);

$regWrongRpId = aegis_webauthn_verify_registration($regCred, $regChallenge, $origin, 'other.example');
t('registration wrong rp id rejected', ($regWrongRpId['ok'] ?? true) === false);

$noUpAuthData = build_auth_data($rpIdHash, 0x40, 0, $es256Cose, $credId); // AT only, no UP
$noUpAttObj = cbor_map_head(3) . cbor_text('fmt') . cbor_text('none')
    . cbor_text('attStmt') . cbor_map_head(0) . cbor_text('authData') . cbor_bytes($noUpAuthData);
$noUpCred = $regCred; $noUpCred['response']['attestationObject'] = b64u($noUpAttObj);
$regNoUp = aegis_webauthn_verify_registration($noUpCred, $regChallenge, $origin, $rpId);
t('registration without user-present rejected', ($regNoUp['ok'] ?? true) === false);

$malformedCred = $regCred; unset($malformedCred['response']['attestationObject']);
$regMalformed = aegis_webauthn_verify_registration($malformedCred, $regChallenge, $origin, $rpId);
t('registration malformed input rejected, not thrown', ($regMalformed['ok'] ?? true) === false);

$rsaOnlyAuthData = build_auth_data($rpIdHash, 0x41, 0, $rs256Cose, $credId);
$rsaAttObj = cbor_map_head(3) . cbor_text('fmt') . cbor_text('none')
    . cbor_text('attStmt') . cbor_map_head(0) . cbor_text('authData') . cbor_bytes($rsaOnlyAuthData);
$rsaCred = $regCred; $rsaCred['response']['attestationObject'] = b64u($rsaAttObj);
$regRsa = aegis_webauthn_verify_registration($rsaCred, $regChallenge, $origin, $rpId);
t('registration non-ES256 key rejected', ($regRsa['ok'] ?? true) === false);
t('registration non-ES256 reason', ($regRsa['reason'] ?? '') === 'unsupported_algorithm');

// full assertion verification (webauthn.get), signed for real with the same keypair

$loginChallenge = b64u(random_bytes(32));
$authDataLogin = build_auth_data($rpIdHash, 0x01, 1); // UP only, no attested credential data (normal for an assertion)
$clientDataLogin = json_encode(['type' => 'webauthn.get', 'challenge' => $loginChallenge, 'origin' => $origin]);
$signedData = $authDataLogin . hash('sha256', $clientDataLogin, true);
openssl_sign($signedData, $loginSig, $privKey, OPENSSL_ALGO_SHA256);

$assertionCred = [
    'id'   => b64u($credId),
    'type' => 'public-key',
    'response' => [
        'clientDataJSON'    => b64u($clientDataLogin),
        'authenticatorData' => b64u($authDataLogin),
        'signature'         => b64u($loginSig),
    ],
];
$stored = ['public_key' => ['x' => base64_encode($kx), 'y' => base64_encode($ky)], 'sign_count' => 0];

$assert = aegis_webauthn_verify_assertion($assertionCred, $stored, $loginChallenge, $origin, $rpId);
t('assertion ok', ($assert['ok'] ?? false) === true);
t('assertion new sign count', ($assert['sign_count'] ?? null) === 1);

$assertBadSig = $assertionCred;
$assertBadSig['response']['signature'] = b64u($loginSig . "\x00");
$r = aegis_webauthn_verify_assertion($assertBadSig, $stored, $loginChallenge, $origin, $rpId);
t('assertion tampered signature rejected', ($r['ok'] ?? true) === false);

$wrongStored = ['public_key' => ['x' => base64_encode($otherX), 'y' => base64_encode($otherY)], 'sign_count' => 0];
$r = aegis_webauthn_verify_assertion($assertionCred, $wrongStored, $loginChallenge, $origin, $rpId);
t('assertion wrong stored key rejected', ($r['ok'] ?? true) === false);

$replayStored = ['public_key' => ['x' => base64_encode($kx), 'y' => base64_encode($ky)], 'sign_count' => 5];
$r = aegis_webauthn_verify_assertion($assertionCred, $replayStored, $loginChallenge, $origin, $rpId);
t('assertion non-increasing counter rejected', ($r['ok'] ?? true) === false);
t('assertion replay reason', ($r['reason'] ?? '') === 'sign_count_replay');

// an authenticator that never uses a counter (both sides report 0) must still be accepted
$authDataLoginZero = build_auth_data($rpIdHash, 0x01, 0);
$signedDataZero = $authDataLoginZero . hash('sha256', $clientDataLogin, true);
openssl_sign($signedDataZero, $sigZero, $privKey, OPENSSL_ALGO_SHA256);
$assertZero = $assertionCred;
$assertZero['response']['authenticatorData'] = b64u($authDataLoginZero);
$assertZero['response']['signature'] = b64u($sigZero);
$zeroStored = ['public_key' => ['x' => base64_encode($kx), 'y' => base64_encode($ky)], 'sign_count' => 0];
$r = aegis_webauthn_verify_assertion($assertZero, $zeroStored, $loginChallenge, $origin, $rpId);
t('assertion zero/zero counter accepted', ($r['ok'] ?? false) === true);

// one-shot session challenges

aegis_mfa_session_ensure();
$c1 = aegis_webauthn_new_challenge('root', 'register');
t('challenge issued', is_string($c1) && strlen($c1) > 0);
$taken = aegis_webauthn_take_challenge('root', 'register');
t('challenge matches on take', $taken === $c1);
$takenAgain = aegis_webauthn_take_challenge('root', 'register');
t('challenge one-shot, gone after take', $takenAgain === null);

aegis_webauthn_new_challenge('root', 'register');
$wrongPurpose = aegis_webauthn_take_challenge('root', 'login');
t('challenge purpose mismatch refused', $wrongPurpose === null);
$stillGone = aegis_webauthn_take_challenge('root', 'register');
t('challenge consumed even on mismatch', $stillGone === null);

aegis_webauthn_new_challenge('root', 'login');
$expired = aegis_webauthn_take_challenge('root', 'login', 300, time() + 301);
t('challenge expires past ttl', $expired === null);

echo "\nwebauthn.test.php: {$pass} passed, {$fail} failed\n";
foreach (glob("$work/flash/*") as $g) @unlink($g);
foreach (glob("$work/sess_*") as $g) @unlink($g);
@rmdir("$work/flash"); @rmdir($work);
exit($fail === 0 ? 0 : 1);
