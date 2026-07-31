<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

// RFC 4648 base32, tolerant of spaces, lowercase and padding for manual entry
function aegis_totp_b32decode(string $b32) {
    static $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(str_replace(' ', '', rtrim($b32, '=')));
    if ($b32 === '') return false;
    $val = 0; $bits = 0; $out = '';
    $len = strlen($b32);
    for ($i = 0; $i < $len; $i++) {
        $p = strpos($map, $b32[$i]);
        if ($p === false) return false;
        $val = ($val << 5) | $p;
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $out .= chr(($val >> $bits) & 0xff);
        }
    }
    return $out;
}

function aegis_totp_b32encode(string $raw): string {
    static $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $val = 0; $bits = 0; $out = '';
    $len = strlen($raw);
    for ($i = 0; $i < $len; $i++) {
        $val = ($val << 8) | ord($raw[$i]);
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $out .= $map[($val >> $bits) & 31];
        }
    }
    if ($bits > 0) $out .= $map[($val << (5 - $bits)) & 31];
    return $out;
}

// RFC 4226 HOTP, the counter is the TOTP timestep
function aegis_totp_hotp(string $secret_raw, int $counter, int $digits = 6): string {
    $hash = hash_hmac('sha1', pack('J', $counter), $secret_raw, true);
    $off  = ord($hash[strlen($hash) - 1]) & 0x0f;
    $val  = ((ord($hash[$off])     & 0x7f) << 24)
          | ((ord($hash[$off + 1]) & 0xff) << 16)
          | ((ord($hash[$off + 2]) & 0xff) << 8)
          |  (ord($hash[$off + 3]) & 0xff);
    return str_pad((string)($val % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

// returns the matched step so the caller can reject replays. compare with === false, step 0 is valid
function aegis_totp_verify_step(string $b32secret, string $code, int $window = 1, int $period = 30, ?int $now = null) {
    $code = preg_replace('/\D/', '', $code);
    if (strlen($code) !== 6) return false;
    $raw = aegis_totp_b32decode($b32secret);
    if ($raw === false || strlen($raw) < 10) return false;
    $step = intdiv($now ?? time(), $period);
    $hit = false;
    for ($i = -$window; $i <= $window; $i++) {
        $s = $step + $i;
        if ($s < 0) continue;

        if (hash_equals(aegis_totp_hotp($raw, $s), $code) && $hit === false) $hit = $s;
    }
    return $hit;
}

function aegis_totp_verify(string $b32secret, string $code, int $window = 1, int $period = 30, ?int $now = null): bool {
    return aegis_totp_verify_step($b32secret, $code, $window, $period, $now) !== false;
}

// 32 base32 chars = 160 bits, the SHA1 size RFC 4226 recommends
function aegis_totp_generate_secret(int $length = 32): string {
    static $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bytes = random_bytes($length);
    $out = '';
    for ($i = 0; $i < $length; $i++) $out .= $map[ord($bytes[$i]) & 31];
    return $out;
}

function aegis_totp_uri(string $secret, string $account, string $issuer = 'Aegis MFA'): string {
    return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
         . '?secret=' . $secret
         . '&issuer=' . rawurlencode($issuer)
         . '&algorithm=SHA1&digits=6&period=30';
}
