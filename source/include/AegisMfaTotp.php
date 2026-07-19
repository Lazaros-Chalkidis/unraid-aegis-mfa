<?php
/*
 * Aegis MFA for Unraid - TOTP core (RFC 6238 / RFC 4226)
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Self-contained, no dependencies. SHA1, 6 digits, 30s period.
 * Every function carries the aegis_totp_ prefix: this file is loaded
 * inside the shared webGUI PHP space and a function redeclare is a
 * fatal that try/catch cannot intercept, so collision avoidance is
 * part of the fail-open design.
 */

// decode RFC 4648 base32, raw bytes or false. tolerant of spaces, lowercase and padding (manual entry)
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

// encode raw bytes to RFC 4648 base32, no padding
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

// HOTP value for a counter (RFC 4226). $secret_raw is decoded bytes
function aegis_totp_hotp(string $secret_raw, int $counter, int $digits = 6): string {
    $hash = hash_hmac('sha1', pack('J', $counter), $secret_raw, true);
    $off  = ord($hash[strlen($hash) - 1]) & 0x0f;
    $val  = ((ord($hash[$off])     & 0x7f) << 24)
          | ((ord($hash[$off + 1]) & 0xff) << 16)
          | ((ord($hash[$off + 2]) & 0xff) << 8)
          |  (ord($hash[$off + 3]) & 0xff);
    return str_pad((string)($val % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

// verify a 6-digit code within +/- $window steps. returns the matched timestep so the caller can persist it
// and reject replays, or false. compare with === false, step 0 is valid
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
        // hash_equals on every slot, constant time, no early exit
        if (hash_equals(aegis_totp_hotp($raw, $s), $code) && $hit === false) $hit = $s;
    }
    return $hit;
}

// convenience wrapper when the caller handles replay tracking
function aegis_totp_verify(string $b32secret, string $code, int $window = 1, int $period = 30, ?int $now = null): bool {
    return aegis_totp_verify_step($b32secret, $code, $window, $period, $now) !== false;
}

// new random base32 secret, 32 chars = 160 bits, the SHA1 size RFC 4226 recommends
function aegis_totp_generate_secret(int $length = 32): string {
    static $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bytes = random_bytes($length);
    $out = '';
    for ($i = 0; $i < $length; $i++) $out .= $map[ord($bytes[$i]) & 31];
    return $out;
}

// otpauth:// URI for the enrolment QR
function aegis_totp_uri(string $secret, string $account, string $issuer = 'Aegis MFA'): string {
    return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
         . '?secret=' . $secret
         . '&issuer=' . rawurlencode($issuer)
         . '&algorithm=SHA1&digits=6&period=30';
}
