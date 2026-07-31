<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaTotp.php';
require_once __DIR__ . '/AegisMfaHelpers.php';

// the gate the patched Unraid files call, true = let through. every error path returns true, never lock anyone out over our bug
function aegis_mfa_passed(): bool {
    try {

        if (!aegis_mfa_enabled()) return true;

        $user = aegis_mfa_current_user();
        if ($user === '') return true;

        $status = aegis_mfa_user_status($user);
        if ($status === 'none') return true;

        if (aegis_mfa_ip_trusted(aegis_mfa_client_ip())) return true;

        if (aegis_mfa_session_verified()) return true;

        if (aegis_mfa_request_is_setup()) return true;

        $amfaPrompt = aegis_mfa_request_is_navigation()
            || (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['aegis_mfa_code']));
        if (!aegis_mfa_enforcing()) {
            return aegis_mfa_session_nudged() || !$amfaPrompt;
        }

        if ($status === 'pending') {
            return aegis_mfa_session_nudged() || !$amfaPrompt;
        }

        return false;

    } catch (\Throwable $e) {

        @error_log('aegis-mfa gate: ' . $e->getMessage());
        return true;
    }
}

// the wizard must stay reachable or locked users loop between /login and the challenge forever
function aegis_mfa_request_is_setup(): bool {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!is_string($uri) || $uri === '') return false;
    return parse_url($uri, PHP_URL_PATH) === '/plugins/aegis.mfa/include/setup.php';
}

// deliberately not exempt: it carries the Disable button, and recovery never needs the webGUI
// verifier is fail-safe, unlike the gate: any error denies. lockout is checked before any crypto so a flood cannot use us as a CPU oracle
function aegis_mfa_verify_submission(string $user, string $code, ?int $now = null): array {
    $now = $now ?? time();
    try {
        $ip = aegis_mfa_client_ip();

        if (aegis_mfa_is_locked($ip, $now)) {
            return ['ok' => false, 'locked' => true, 'retry_after' => aegis_mfa_lock_remaining($ip, $now)];
        }

        $code = preg_replace('/\s+/', '', $code);
        $ok = false;
        $method = 'app code';

        if (aegis_mfa_looks_like_backup_code($code)) {
            $method = 'backup code';
            $ok = aegis_mfa_consume_backup_code($user, $code);
        } else {
            $secret = aegis_mfa_get_secret($user);
            if ($secret !== null) {
                $step = aegis_totp_verify_step($secret, $code, 1);
                if ($step !== false) {

                    $ok = aegis_mfa_set_last_step($user, $step);

                }
            }
        }

        if ($ok) {
            aegis_mfa_clear_failures($ip);
            aegis_mfa_mark_verified($user);

            // which credential was used belongs in the log: a backup code is a recovery event
            $detail = $method === 'backup code'
                ? 'backup code, ' . aegis_mfa_backup_codes_remaining($user) . ' left'
                : $method;
            @syslog(LOG_INFO, "aegis-mfa: 2FA success for $user from $ip ($detail)");
            return ['ok' => true, 'method' => $method];
        }

        $remaining = aegis_mfa_record_failure($ip, $user, $now);
        @syslog(LOG_WARNING, "aegis-mfa: 2FA failure for $user from $ip ($method)");
        if ($remaining <= 0) {
            return ['ok' => false, 'locked' => true, 'retry_after' => aegis_mfa_lock_remaining($ip, $now)];
        }
        return ['ok' => false, 'remaining' => $remaining];

    } catch (\Throwable $e) {

        @error_log('aegis-mfa verify: ' . $e->getMessage());
        return ['ok' => false, 'remaining' => 1];
    }
}

function aegis_mfa_lock_remaining(string $ip, ?int $now = null): int {
    $d = aegis_mfa_read_json(aegis_mfa_lockout_path());
    $until = (int)($d['failures'][$ip]['locked_until'] ?? 0);
    return max(0, $until - ($now ?? time()));
}

function aegis_mfa_looks_like_backup_code(string $code): bool {
    return (bool)preg_match('/^[0-9a-f]{5}-?[0-9a-f]{5}$/i', $code);
}

function aegis_mfa_generate_backup_codes(int $n = 10): array {
    $plain = []; $hashed = [];
    for ($i = 0; $i < $n; $i++) {
        $raw = bin2hex(random_bytes(5));
        $fmt = substr($raw, 0, 5) . '-' . substr($raw, 5);
        $plain[]  = $fmt;
        $hashed[] = password_hash($raw, PASSWORD_DEFAULT);
    }
    return [$plain, $hashed];
}

// single use, the matched hash is removed on success
function aegis_mfa_consume_backup_code(string $user, string $code): bool {
    $norm = strtolower(str_replace('-', '', $code));
    if (!preg_match('/^[0-9a-f]{10}$/', $norm)) return false;

    $matchedIndex = -1;

    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $codes = $sec['users'][$user]['backup_codes'] ?? [];
    $used  = $sec['users'][$user]['backup_codes_used'] ?? [];
    if (!is_array($codes)) return false;
    foreach ($codes as $idx => $hash) {
        if (in_array($idx, $used, true)) continue;
        if (is_string($hash) && password_verify($norm, $hash)) { $matchedIndex = $idx; break; }
    }
    if ($matchedIndex < 0) return false;

    $consumed = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $matchedIndex, &$consumed) {
            $u = $s['users'][$user] ?? null;
            if (!is_array($u)) return $s;
            $used = $u['backup_codes_used'] ?? [];
            if (in_array($matchedIndex, $used, true)) return $s;
            $used[] = $matchedIndex;
            $s['users'][$user]['backup_codes_used'] = $used;
            $consumed = true;
            return $s;
        });
    return $consumed;
}

function aegis_mfa_backup_codes_remaining(string $user): int {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $codes = $sec['users'][$user]['backup_codes'] ?? [];
    $used  = $sec['users'][$user]['backup_codes_used'] ?? [];
    if (!is_array($codes)) return 0;
    return max(0, count($codes) - count(is_array($used) ? $used : []));
}
