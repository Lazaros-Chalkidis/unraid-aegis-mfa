<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaGate.php';

function aegis_mfa_csrf_token(): string {
    aegis_mfa_session_ensure();
    if (empty($_SESSION['aegis_mfa_csrf']) || !is_string($_SESSION['aegis_mfa_csrf'])) {
        $_SESSION['aegis_mfa_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['aegis_mfa_csrf'];
}

function aegis_mfa_csrf_check(string $token): bool {
    $have = $_SESSION['aegis_mfa_csrf'] ?? '';
    return is_string($have) && $have !== '' && hash_equals($have, $token);
}

// the in-progress secret and codes live in the session, never on disk, so an abandoned wizard leaves no trace
function aegis_mfa_begin_enrollment(string $user, string $issuer = 'Aegis MFA', ?string $host = null): array {
    aegis_mfa_session_ensure();
    $secret = aegis_totp_generate_secret();
    list($plain, $hashed) = aegis_mfa_generate_backup_codes(10);
    $_SESSION['aegis_mfa_enroll'] = [
        'user'          => $user,
        'secret'        => $secret,
        'backup_plain'  => $plain,
        'backup_hashed' => $hashed,
        'totp_ok'       => false,
        'started'       => time(),
    ];
    $account = $user . ($host ? '@' . $host : '');
    return [
        'secret'       => $secret,
        'uri'          => aegis_totp_uri($secret, $account, $issuer),
        'backup_codes' => $plain,
    ];
}

function aegis_mfa_enroll_state(): ?array {
    $e = $_SESSION['aegis_mfa_enroll'] ?? null;
    return is_array($e) ? $e : null;
}

function aegis_mfa_verify_enrollment_totp(string $code): bool {
    $e = aegis_mfa_enroll_state();
    if ($e === null || empty($e['secret'])) return false;
    if (!aegis_totp_verify($e['secret'], $code, 1)) return false;
    $_SESSION['aegis_mfa_enroll']['totp_ok'] = true;
    return true;
}

// only a code-confirmed enrolment is written to secrets.json
function aegis_mfa_commit_enrollment(string $backupConfirm): array {
    $e = aegis_mfa_enroll_state();
    if ($e === null || empty($e['secret']) || empty($e['user'])) {
        return ['ok' => false, 'reason' => 'no_enrollment'];
    }
    if (empty($e['totp_ok'])) {
        return ['ok' => false, 'reason' => 'totp_not_verified'];
    }
    $norm = strtolower(str_replace('-', '', $backupConfirm));
    $usedIndex = -1;
    foreach ($e['backup_plain'] as $i => $code) {
        if (strtolower(str_replace('-', '', $code)) === $norm) { $usedIndex = $i; break; }
    }
    if ($usedIndex < 0) return ['ok' => false, 'reason' => 'bad_backup_confirm'];

    $user = $e['user'];
    $ok = aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $e, $usedIndex) {
            if (!isset($sec['users']) || !is_array($sec['users'])) $sec['users'] = [];
            $sec['users'][$user] = [
                'status'            => 'enrolled',
                'secret'            => $e['secret'],
                'algorithm'         => 'SHA1',
                'digits'            => 6,
                'period'            => 30,
                'enrolled_at'       => time(),
                'last_step'         => 0,
                'backup_codes'      => $e['backup_hashed'],
                'backup_codes_used' => [$usedIndex],
            ];
            if (!isset($sec['version'])) $sec['version'] = 1;
            return $sec;
        });
    if (!$ok) return ['ok' => false, 'reason' => 'write_failed'];

    unset($_SESSION['aegis_mfa_enroll']);
    return ['ok' => true];
}

function aegis_mfa_cancel_enrollment(): void {
    unset($_SESSION['aegis_mfa_enroll']);
}

// lost-authenticator path: one-time token, still requires a password login
function aegis_mfa_create_bypass_token(string $user, int $ttl = 86400): ?string {
    $token = bin2hex(random_bytes(24));
    $ok = aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $token, $ttl) {
            if (!isset($sec['users'][$user]) || !is_array($sec['users'][$user])) {
                $sec['users'][$user] = ['status' => 'pending'];
            }
            $sec['users'][$user]['bypass_hash']  = password_hash($token, PASSWORD_DEFAULT);
            $sec['users'][$user]['bypass_until'] = time() + $ttl;
            if (!isset($sec['version'])) $sec['version'] = 1;
            return $sec;
        });
    return $ok ? $token : null;
}

function aegis_mfa_consume_bypass_token(string $user, string $token, ?int $now = null): bool {
    $now = $now ?? time();
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $u = $sec['users'][$user] ?? null;
    if (!is_array($u)) return false;
    $hash  = $u['bypass_hash'] ?? '';
    $until = (int)($u['bypass_until'] ?? 0);
    if (!is_string($hash) || $hash === '' || $until < $now) return false;
    if (!password_verify($token, $hash)) return false;

    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user) {
            unset($sec['users'][$user]['bypass_hash'], $sec['users'][$user]['bypass_until']);
            return $sec;
        });
    return true;
}
