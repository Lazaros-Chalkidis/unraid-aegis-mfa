<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaGate.php';
require_once __DIR__ . '/AegisMfaWebauthn.php';

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

// in-progress secret/codes/passkey live in the session, never on disk - an abandoned wizard leaves no trace
// $method is 'totp' (default, unchanged behaviour) or 'passkey'
function aegis_mfa_begin_enrollment(string $user, string $issuer = 'Aegis MFA', ?string $host = null, string $method = 'totp'): array {
    aegis_mfa_session_ensure();
    list($plain, $hashed) = aegis_mfa_generate_backup_codes(10);
    $state = [
        'user'          => $user,
        'method'        => $method,
        'backup_plain'  => $plain,
        'backup_hashed' => $hashed,
        'totp_ok'       => false,
        'passkey_ok'    => false,
        'passkey_cred'  => null,
        'started'       => time(),
    ];
    $result = ['method' => $method, 'backup_codes' => $plain];

    if ($method === 'totp') {
        $secret = aegis_totp_generate_secret();
        $state['secret'] = $secret;
        $account = $user . ($host ? '@' . $host : '');
        $result['secret'] = $secret;
        $result['uri'] = aegis_totp_uri($secret, $account, $issuer);
    }

    $_SESSION['aegis_mfa_enroll'] = $state;
    return $result;
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

// completes the passkey half of the wizard: verifies against this session's challenge, holds the credential until backup-code confirmation commits it
function aegis_mfa_verify_enrollment_passkey(array $credentialResponse, string $expectedOrigin): array {
    $e = aegis_mfa_enroll_state();
    if ($e === null || ($e['method'] ?? '') !== 'passkey' || empty($e['user'])) {
        return ['ok' => false, 'reason' => 'no_enrollment'];
    }
    $challenge = aegis_webauthn_take_challenge($e['user'], 'register');
    if ($challenge === null) return ['ok' => false, 'reason' => 'challenge_expired'];

    $r = aegis_webauthn_verify_registration($credentialResponse, $challenge, $expectedOrigin, aegis_mfa_webauthn_rp_id());
    if (!($r['ok'] ?? false)) return $r;

    $_SESSION['aegis_mfa_enroll']['passkey_ok']   = true;
    $_SESSION['aegis_mfa_enroll']['passkey_cred'] = [
        'id'           => aegis_webauthn_b64url_encode($r['credential_id']),
        'public_key'   => $r['public_key'],
        'sign_count'   => $r['sign_count'],
        'created_at'   => time(),
        'last_used_at' => null,
        'label'        => 'Passkey',
    ];
    return ['ok' => true];
}

// only a confirmed enrolment (verified TOTP secret or verified passkey) is written to secrets.json, backup code confirmation required either way
function aegis_mfa_commit_enrollment(string $backupConfirm): array {
    $e = aegis_mfa_enroll_state();
    if ($e === null || empty($e['user'])) {
        return ['ok' => false, 'reason' => 'no_enrollment'];
    }
    $method = $e['method'] ?? 'totp';
    if ($method === 'totp' && empty($e['secret'])) {
        return ['ok' => false, 'reason' => 'no_enrollment'];
    }
    if ($method === 'totp' && empty($e['totp_ok'])) {
        return ['ok' => false, 'reason' => 'totp_not_verified'];
    }
    if ($method === 'passkey' && (empty($e['passkey_ok']) || empty($e['passkey_cred']))) {
        return ['ok' => false, 'reason' => 'passkey_not_verified'];
    }
    if ($method !== 'totp' && $method !== 'passkey') {
        return ['ok' => false, 'reason' => 'no_enrollment'];
    }

    $norm = strtolower(str_replace('-', '', $backupConfirm));
    $usedIndex = -1;
    foreach ($e['backup_plain'] as $i => $code) {
        if (strtolower(str_replace('-', '', $code)) === $norm) { $usedIndex = $i; break; }
    }
    if ($usedIndex < 0) return ['ok' => false, 'reason' => 'bad_backup_confirm'];

    $user = $e['user'];
    $ok = aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $e, $method, $usedIndex) {
            if (!isset($sec['users']) || !is_array($sec['users'])) $sec['users'] = [];
            $rec = [
                'status'            => 'enrolled',
                'enrolled_at'       => time(),
                'backup_codes'      => $e['backup_hashed'],
                'backup_codes_used' => [$usedIndex],
            ];
            if ($method === 'totp') {
                $rec['secret']    = $e['secret'];
                $rec['algorithm'] = 'SHA1';
                $rec['digits']    = 6;
                $rec['period']    = 30;
                $rec['last_step'] = 0;
                $rec['passkeys']  = [];
            } else {
                $rec['passkeys'] = [$e['passkey_cred']];
            }
            $sec['users'][$user] = $rec;
            if (!isset($sec['version'])) $sec['version'] = 1;
            return $sec;
        });
    if (!$ok) return ['ok' => false, 'reason' => 'write_failed'];

    unset($_SESSION['aegis_mfa_enroll']);
    return ['ok' => true];
}

// access rule for setup/registration: a valid bypass token, an already-verified session, or no completed enrolment yet (pending/locked/none)
// shared by setup.php and the webauthn.* endpoints, so this decision lives in one place, not two that can drift
function aegis_mfa_setup_access_ok(string $user): bool {
    if ($user === '') return false;
    $tok = $_SESSION['aegis_mfa_token_ok'] ?? null;
    if (is_array($tok) && ($tok['user'] ?? '') === $user && (int)($tok['until'] ?? 0) > time()) return true;
    if (aegis_mfa_session_verified()) return true;
    return in_array(aegis_mfa_user_status($user), ['pending', 'locked', 'none'], true);
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
