<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaHelpers.php';

class AegisWebauthnError extends \RuntimeException {}

function aegis_webauthn_b64url_encode(string $raw): string {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function aegis_webauthn_b64url_decode(string $s) {
    $s = strtr($s, '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad) $s .= str_repeat('=', 4 - $pad);
    $out = base64_decode($s, true);
    return $out === false ? null : $out;
}

// CBOR (RFC 8949), definite-length items only - anything indefinite-length is refused, not half-handled
function aegis_cbor_slice(string $d, int &$off, int $n): string {
    if ($n < 0 || $off + $n > strlen($d)) throw new AegisWebauthnError('cbor: truncated');
    $s = substr($d, $off, $n);
    $off += $n;
    return $s;
}

function aegis_cbor_read_arg(string $d, int &$off, int $info): int {
    if ($info < 24) return $info;
    if ($info === 24) return ord(aegis_cbor_slice($d, $off, 1));
    if ($info === 25) { $b = aegis_cbor_slice($d, $off, 2); return (ord($b[0]) << 8) | ord($b[1]); }
    if ($info === 26) {
        $b = aegis_cbor_slice($d, $off, 4);
        return (ord($b[0]) << 24) | (ord($b[1]) << 16) | (ord($b[2]) << 8) | ord($b[3]);
    }
    if ($info === 27) {
        $b = aegis_cbor_slice($d, $off, 8);
        $n = 0;
        for ($i = 0; $i < 8; $i++) $n = ($n << 8) | ord($b[$i]);
        if ($n < 0) throw new AegisWebauthnError('cbor: length too large');
        return $n;
    }
    throw new AegisWebauthnError('cbor: unsupported/indefinite length');
}

// returns int, string (byte or text string, indistinguishable once decoded), bool, null,
// a list (CBOR array) or an assoc array keyed by int/string (CBOR map)
function aegis_cbor_decode_item(string $d, int &$off, int $depth = 0) {
    if ($depth > 16) throw new AegisWebauthnError('cbor: too deeply nested');
    if ($off >= strlen($d)) throw new AegisWebauthnError('cbor: truncated');
    $ib = ord($d[$off]);
    $off++;
    $major = $ib >> 5;
    $info = $ib & 0x1f;

    switch ($major) {
        case 0: return aegis_cbor_read_arg($d, $off, $info);
        case 1: return -1 - aegis_cbor_read_arg($d, $off, $info);
        case 2: { $n = aegis_cbor_read_arg($d, $off, $info); return aegis_cbor_slice($d, $off, $n); }
        case 3: { $n = aegis_cbor_read_arg($d, $off, $info); return aegis_cbor_slice($d, $off, $n); }
        case 4: {
            $n = aegis_cbor_read_arg($d, $off, $info);
            if ($n > 4096) throw new AegisWebauthnError('cbor: array too large');
            $out = [];
            for ($i = 0; $i < $n; $i++) $out[] = aegis_cbor_decode_item($d, $off, $depth + 1);
            return $out;
        }
        case 5: {
            $n = aegis_cbor_read_arg($d, $off, $info);
            if ($n > 4096) throw new AegisWebauthnError('cbor: map too large');
            $out = [];
            for ($i = 0; $i < $n; $i++) {
                $k = aegis_cbor_decode_item($d, $off, $depth + 1);
                $v = aegis_cbor_decode_item($d, $off, $depth + 1);
                if (!is_int($k) && !is_string($k)) throw new AegisWebauthnError('cbor: unsupported map key type');
                $out[$k] = $v;
            }
            return $out;
        }
        case 7:
            if ($info === 20) return false;
            if ($info === 21) return true;
            if ($info === 22) return null;
            throw new AegisWebauthnError('cbor: unsupported simple/float type');
        default:
            throw new AegisWebauthnError('cbor: unsupported major type ' . $major);
    }
}

// decodes exactly one item starting at offset 0 and requires the whole buffer consumed
function aegis_cbor_decode(string $d) {
    $off = 0;
    $v = aegis_cbor_decode_item($d, $off);
    if ($off !== strlen($d)) throw new AegisWebauthnError('cbor: trailing bytes');
    return $v;
}

// returns ['x' => raw 32 bytes, 'y' => raw 32 bytes] or null if this key is not EC2/P-256/ES256
function aegis_webauthn_cose_ec2_es256(array $cose): ?array {
    $kty = $cose[1] ?? null;   // 1 = kty
    $alg = $cose[3] ?? null;   // 3 = alg
    $crv = $cose[-1] ?? null;  // -1 = crv
    $x   = $cose[-2] ?? null;  // -2 = x
    $y   = $cose[-3] ?? null;  // -3 = y
    if ($kty !== 2 || $alg !== -7 || $crv !== 1) return null; // EC2, ES256, P-256 only
    if (!is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) return null;
    return ['x' => $x, 'y' => $y];
}

// minimal DER, just enough to wrap a raw P-256 point as an SPKI openssl_pkey_get_public() accepts
function aegis_der_len(int $n): string {
    if ($n < 0x80) return chr($n);
    $bytes = '';
    while ($n > 0) { $bytes = chr($n & 0xff) . $bytes; $n >>= 8; }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function aegis_der_tlv(int $tag, string $content): string {
    return chr($tag) . aegis_der_len(strlen($content)) . $content;
}

function aegis_webauthn_p256_spki_der(string $x32, string $y32): string {
    $oidEcPublicKey = "\x2a\x86\x48\xce\x3d\x02\x01";       // 1.2.840.10045.2.1 (id-ecPublicKey)
    $oidPrime256v1  = "\x2a\x86\x48\xce\x3d\x03\x01\x07";   // 1.2.840.10045.3.1.7 (prime256v1)
    $algId = aegis_der_tlv(0x30, aegis_der_tlv(0x06, $oidEcPublicKey) . aegis_der_tlv(0x06, $oidPrime256v1));
    $point = "\x04" . $x32 . $y32; // uncompressed EC point
    $bitString = aegis_der_tlv(0x03, "\x00" . $point); // 0x00 = zero unused bits
    return aegis_der_tlv(0x30, $algId . $bitString);
}

function aegis_webauthn_es256_pem_from_xy(string $x32, string $y32): string {
    $der = aegis_webauthn_p256_spki_der($x32, $y32);
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

// $derSignature is the raw DER-encoded ECDSA signature WebAuthn already produces, no re-encoding needed
function aegis_webauthn_es256_verify(string $signedData, string $derSignature, string $x32, string $y32): bool {
    if (strlen($x32) !== 32 || strlen($y32) !== 32) return false;
    $pub = @openssl_pkey_get_public(aegis_webauthn_es256_pem_from_xy($x32, $y32));
    if ($pub === false) return false;
    return @openssl_verify($signedData, $derSignature, $pub, OPENSSL_ALGO_SHA256) === 1;
}

// authenticatorData (WebAuthn L2 §6.1) parsing
function aegis_webauthn_parse_auth_data(string $authData): array {
    if (strlen($authData) < 37) throw new AegisWebauthnError('authData: too short');
    $off = 0;
    $rpIdHash = substr($authData, $off, 32); $off += 32;
    $flags = ord($authData[$off]); $off += 1;
    $scBytes = substr($authData, $off, 4); $off += 4;
    $signCount = (ord($scBytes[0]) << 24) | (ord($scBytes[1]) << 16) | (ord($scBytes[2]) << 8) | ord($scBytes[3]);

    $up = (bool)($flags & 0x01); // user present
    $uv = (bool)($flags & 0x04); // user verified
    $at = (bool)($flags & 0x40); // attested credential data included

    $aaguid = null; $credId = null; $coseKey = null;
    if ($at) {
        if (strlen($authData) < $off + 18) throw new AegisWebauthnError('authData: truncated attested cred data');
        $aaguid = substr($authData, $off, 16); $off += 16;
        $credIdLen = (ord($authData[$off]) << 8) | ord($authData[$off + 1]); $off += 2;
        if (strlen($authData) < $off + $credIdLen) throw new AegisWebauthnError('authData: truncated credential id');
        $credId = substr($authData, $off, $credIdLen); $off += $credIdLen;
        $coseKey = aegis_cbor_decode_item($authData, $off);
        if (!is_array($coseKey)) throw new AegisWebauthnError('authData: bad COSE key');
        // any extension data (ED flag) follows and is intentionally left unparsed, we don't use extensions
    }

    return [
        'rp_id_hash' => $rpIdHash, 'flags' => $flags, 'sign_count' => $signCount,
        'up' => $up, 'uv' => $uv, 'at' => $at,
        'aaguid' => $aaguid, 'cred_id' => $credId, 'cose_key' => $coseKey,
    ];
}

function aegis_webauthn_parse_client_data(string $json): array {
    $d = json_decode($json, true);
    if (!is_array($d)) throw new AegisWebauthnError('clientData: not JSON');
    foreach (['type', 'challenge', 'origin'] as $k) {
        if (!isset($d[$k]) || !is_string($d[$k])) throw new AegisWebauthnError("clientData: missing $k");
    }
    return $d;
}

function aegis_webauthn_check_client_data(array $cd, string $expectedType, string $expectedChallengeB64Url, string $expectedOrigin): void {
    if (!hash_equals($expectedType, $cd['type'])) throw new AegisWebauthnError('clientData: wrong type');
    if (!hash_equals($expectedChallengeB64Url, $cd['challenge'])) throw new AegisWebauthnError('clientData: challenge mismatch');
    if (!hash_equals($expectedOrigin, $cd['origin'])) throw new AegisWebauthnError('clientData: origin mismatch');
}

// same session-namespace pattern as aegis_mfa_csrf_token(), bound to a user+purpose so a login challenge can't be replayed as a registration challenge
function aegis_webauthn_new_challenge(string $user, string $purpose): string {
    aegis_mfa_session_ensure();
    $b64 = aegis_webauthn_b64url_encode(random_bytes(32));
    $_SESSION['aegis_mfa_webauthn_challenge'] = [
        'user' => $user, 'purpose' => $purpose, 'challenge' => $b64, 'at' => time(),
    ];
    return $b64;
}

// one-shot: consumed whether or not it ends up matching, so a stale tab can never retry silently
function aegis_webauthn_take_challenge(string $user, string $purpose, int $ttl = 300, ?int $now = null): ?string {
    $c = $_SESSION['aegis_mfa_webauthn_challenge'] ?? null;
    unset($_SESSION['aegis_mfa_webauthn_challenge']);
    if (!is_array($c)) return null;
    if (($c['user'] ?? '') !== $user || ($c['purpose'] ?? '') !== $purpose) return null;
    if (($now ?? time()) - (int)($c['at'] ?? 0) > $ttl) return null;
    $ch = $c['challenge'] ?? null;
    return is_string($ch) ? $ch : null;
}

// attestation itself is never verified (no trust-anchor chains), only authData - trust here is the
// browser's own WebAuthn UI and the user's gesture, which is how most self-hosted RPs operate
// $cred is the JSON-decoded PublicKeyCredential from navigator.credentials.create()
function aegis_webauthn_verify_registration(array $cred, string $expectedChallengeB64Url, string $expectedOrigin, string $rpId): array {
    try {
        $clientDataB64 = $cred['response']['clientDataJSON'] ?? null;
        $attObjB64 = $cred['response']['attestationObject'] ?? null;
        if (!is_string($clientDataB64) || !is_string($attObjB64)) return ['ok' => false, 'reason' => 'malformed'];

        $clientDataRaw = aegis_webauthn_b64url_decode($clientDataB64);
        $attObjRaw = aegis_webauthn_b64url_decode($attObjB64);
        if ($clientDataRaw === null || $attObjRaw === null) return ['ok' => false, 'reason' => 'malformed'];

        $cd = aegis_webauthn_parse_client_data($clientDataRaw);
        aegis_webauthn_check_client_data($cd, 'webauthn.create', $expectedChallengeB64Url, $expectedOrigin);

        $attObj = aegis_cbor_decode($attObjRaw);
        if (!is_array($attObj) || !isset($attObj['authData']) || !is_string($attObj['authData'])) {
            return ['ok' => false, 'reason' => 'malformed'];
        }
        $authData = aegis_webauthn_parse_auth_data($attObj['authData']);

        if (!hash_equals(hash('sha256', $rpId, true), $authData['rp_id_hash'])) {
            return ['ok' => false, 'reason' => 'rp_id_mismatch'];
        }
        if (!$authData['up']) return ['ok' => false, 'reason' => 'user_not_present'];
        if (!$authData['at'] || $authData['cose_key'] === null || $authData['cred_id'] === null) {
            return ['ok' => false, 'reason' => 'no_credential'];
        }

        $ec = aegis_webauthn_cose_ec2_es256($authData['cose_key']);
        if ($ec === null) return ['ok' => false, 'reason' => 'unsupported_algorithm'];

        return [
            'ok'            => true,
            'credential_id' => $authData['cred_id'],
            'public_key'    => ['kty' => 2, 'crv' => 1, 'x' => base64_encode($ec['x']), 'y' => base64_encode($ec['y'])],
            'sign_count'    => $authData['sign_count'],
            'uv'            => $authData['uv'],
        ];
    } catch (\Throwable $e) {
        return ['ok' => false, 'reason' => 'error'];
    }
}

// $stored is the previously-registered passkey record this credential id resolved to
// (['public_key' => ['x'=>base64,'y'=>base64], 'sign_count' => int, ...])
function aegis_webauthn_verify_assertion(array $cred, array $stored, string $expectedChallengeB64Url, string $expectedOrigin, string $rpId): array {
    try {
        $clientDataB64 = $cred['response']['clientDataJSON'] ?? null;
        $authDataB64 = $cred['response']['authenticatorData'] ?? null;
        $sigB64 = $cred['response']['signature'] ?? null;
        if (!is_string($clientDataB64) || !is_string($authDataB64) || !is_string($sigB64)) {
            return ['ok' => false, 'reason' => 'malformed'];
        }

        $clientDataRaw = aegis_webauthn_b64url_decode($clientDataB64);
        $authDataRaw = aegis_webauthn_b64url_decode($authDataB64);
        $sig = aegis_webauthn_b64url_decode($sigB64);
        if ($clientDataRaw === null || $authDataRaw === null || $sig === null) {
            return ['ok' => false, 'reason' => 'malformed'];
        }

        $cd = aegis_webauthn_parse_client_data($clientDataRaw);
        aegis_webauthn_check_client_data($cd, 'webauthn.get', $expectedChallengeB64Url, $expectedOrigin);

        $authData = aegis_webauthn_parse_auth_data($authDataRaw);
        if (!hash_equals(hash('sha256', $rpId, true), $authData['rp_id_hash'])) {
            return ['ok' => false, 'reason' => 'rp_id_mismatch'];
        }
        if (!$authData['up']) return ['ok' => false, 'reason' => 'user_not_present'];

        $x = base64_decode((string)($stored['public_key']['x'] ?? ''), true);
        $y = base64_decode((string)($stored['public_key']['y'] ?? ''), true);
        if ($x === false || $y === false || strlen($x) !== 32 || strlen($y) !== 32) {
            return ['ok' => false, 'reason' => 'bad_stored_key'];
        }

        $signedData = $authDataRaw . hash('sha256', $clientDataRaw, true);
        if (!aegis_webauthn_es256_verify($signedData, $sig, $x, $y)) {
            return ['ok' => false, 'reason' => 'bad_signature'];
        }

        // a strictly increasing counter is required once either side has ever reported non-zero;
        // an authenticator that never uses one (many platform authenticators) reports 0 forever
        $storedCount = (int)($stored['sign_count'] ?? 0);
        $newCount = (int)$authData['sign_count'];
        if (($storedCount > 0 || $newCount > 0) && $newCount <= $storedCount) {
            return ['ok' => false, 'reason' => 'sign_count_replay'];
        }

        return ['ok' => true, 'sign_count' => $newCount];
    } catch (\Throwable $e) {
        return ['ok' => false, 'reason' => 'error'];
    }
}

// option builders and passkey lookups, shared by the wizard, Settings "add a passkey", and login
function aegis_mfa_webauthn_passkeys(string $user): array {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $pk = $sec['users'][$user]['passkeys'] ?? [];
    return is_array($pk) ? $pk : [];
}

function aegis_mfa_webauthn_find_passkey(string $user, string $credentialIdB64Url): ?array {
    foreach (aegis_mfa_webauthn_passkeys($user) as $pk) {
        if (is_array($pk) && ($pk['id'] ?? '') === $credentialIdB64Url) return $pk;
    }
    return null;
}

// creation options for navigator.credentials.create(). id/challenge/user.id are base64url
// text here, the client JS decodes them to BufferSource before the actual browser call
function aegis_mfa_webauthn_creation_options(string $user, string $displayName): array {
    aegis_mfa_session_ensure();
    $exclude = [];
    foreach (aegis_mfa_webauthn_passkeys($user) as $pk) {
        if (is_array($pk) && is_string($pk['id'] ?? null)) $exclude[] = ['type' => 'public-key', 'id' => $pk['id']];
    }
    return [
        'challenge'              => aegis_webauthn_new_challenge($user, 'register'),
        'rp'                     => ['id' => aegis_mfa_webauthn_rp_id(), 'name' => 'Aegis MFA'],
        // a fresh random handle per ceremony is fine: we never rely on discoverable/usernameless
        // credentials, every login passes an explicit allowCredentials list we already stored
        'user'                   => ['id' => aegis_webauthn_b64url_encode(random_bytes(16)), 'name' => $user, 'displayName' => $displayName],
        'pubKeyCredParams'       => [['type' => 'public-key', 'alg' => -7]], // ES256 only
        'excludeCredentials'     => $exclude,
        'authenticatorSelection' => ['userVerification' => 'preferred'],
        'timeout'                => 60000,
        'attestation'            => 'none',
    ];
}

// request options for navigator.credentials.get()
function aegis_mfa_webauthn_request_options(string $user): array {
    aegis_mfa_session_ensure();
    $allow = [];
    foreach (aegis_mfa_webauthn_passkeys($user) as $pk) {
        if (is_array($pk) && is_string($pk['id'] ?? null)) $allow[] = ['type' => 'public-key', 'id' => $pk['id']];
    }
    return [
        'challenge'        => aegis_webauthn_new_challenge($user, 'login'),
        'rpId'             => aegis_mfa_webauthn_rp_id(),
        'allowCredentials' => $allow,
        'userVerification' => 'preferred',
        'timeout'          => 60000,
    ];
}

// persists the post-verification state of a successful assertion: new sign count and last-used time
function aegis_mfa_webauthn_record_use(string $user, string $credentialIdB64Url, int $newCount, ?int $now = null): bool {
    $wrote = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $credentialIdB64Url, $newCount, $now, &$wrote) {
            $pks = $sec['users'][$user]['passkeys'] ?? null;
            if (!is_array($pks)) return $sec;
            foreach ($pks as $i => $pk) {
                if (!is_array($pk) || ($pk['id'] ?? '') !== $credentialIdB64Url) continue;
                $sec['users'][$user]['passkeys'][$i]['sign_count']   = $newCount;
                $sec['users'][$user]['passkeys'][$i]['last_used_at'] = $now ?? time();
                $wrote = true;
                break;
            }
            return $sec;
        });
    return $wrote;
}
