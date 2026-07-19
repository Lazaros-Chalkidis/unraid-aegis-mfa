<?php
/*
 * Aegis MFA for Unraid - authentication gate
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This is the entry point the patched Unraid files call. The single
 * most important contract in the whole plugin:
 *
 *   aegis_mfa_passed() returns TRUE  -> let the request through
 *                      returns FALSE -> challenge for 2FA
 *
 * It must NEVER throw and must NEVER return false by accident. Every
 * error path resolves to TRUE (allow). The caller additionally wraps
 * this in try/catch and treats only === false as "challenge", so a
 * fatal-that-somehow-escapes still fails open.
 */

require_once __DIR__ . '/AegisMfaTotp.php';
require_once __DIR__ . '/AegisMfaHelpers.php';

// the gate. called after Unraid confirmed the password, decides if the request also satisfies 2FA. check order is deliberate
function aegis_mfa_passed(): bool {
    try {
        // 1. plugin off or USB rescue flag -> allow, the fail-open switch
        if (!aegis_mfa_enabled()) return true;

        // 2. no resolvable user -> not our job, we only gate password-authenticated sessions
        $user = aegis_mfa_current_user();
        if ($user === '') return true;

        // 3. user not tracked at all -> allow
        // none = no secret, pending = in grace, locked = grace expired, enrolled = must pass 2FA
        $status = aegis_mfa_user_status($user);
        if ($status === 'none') return true;

        // 4. trusted LAN -> allow, skips the code and the setup nudge
        if (aegis_mfa_ip_trusted(aegis_mfa_client_ip())) return true;

        // 5. already passed 2FA this session as this user -> allow
        if (aegis_mfa_session_verified()) return true;

        // 6. the wizard must stay reachable or locked and pending users loop between /login and the challenge forever.
        // It authorises on its own, see setup.php
        if (aegis_mfa_request_is_setup()) return true;

        // 7. the settings page and its POSTs stay reachable too, or MFA blocks the admin from the Disable button.
        // It sits behind the password login and its own CSRF, nothing protected leaks
        if (aegis_mfa_request_is_own_settings()) return true;

        // 8. dry-run never blocks. only top-level navigations bounce to /login once per session, assets and XHR pass,
        // or an open tab floods the nginx auth rate limit. a POST carrying our code field passes so the challenge can check it
        $amfaPrompt = aegis_mfa_request_is_navigation()
            || (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['aegis_mfa_code']));
        if (!aegis_mfa_enforcing()) {
            return aegis_mfa_session_nudged() || !$amfaPrompt;
        }

        // 9. grace running: same once-per-session navigation-only bounce, enrolment is forced only when it flips to locked
        if ($status === 'pending') {
            return aegis_mfa_session_nudged() || !$amfaPrompt;
        }

        // enrolled + enforcing + not LAN + not verified -> challenge. locked lands here too, the view routes it to setup
        return false;

    } catch (\Throwable $e) {
        // ANY failure -> allow. never lock anyone out because of our bug
        @error_log('aegis-mfa gate: ' . $e->getMessage());
        return true;
    }
}

// true when the original request targets the setup wizard. strict path equality, any path trick just fails to match
function aegis_mfa_request_is_setup(): bool {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!is_string($uri) || $uri === '') return false;
    return parse_url($uri, PHP_URL_PATH) === '/plugins/aegis.mfa/include/setup.php';
}

// true for the plugin's own settings page, /Settings/AegisMfa, same strict equality
function aegis_mfa_request_is_own_settings(): bool {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if (!is_string($uri) || $uri === '') return false;
    $path = parse_url($uri, PHP_URL_PATH);
    return $path === '/Settings/AegisMfa'
        || $path === '/plugins/aegis.mfa/AegisMfa.page';
}

// challenge verification for the form POST. never throws, returns ok / locked+retry_after / remaining
function aegis_mfa_verify_submission(string $user, string $code, ?int $now = null): array {
    $now = $now ?? time();
    try {
        $ip = aegis_mfa_client_ip();

        // lockout first, before any crypto effort: a flood cannot use us as a CPU oracle or brute past the lock
        if (aegis_mfa_is_locked($ip, $now)) {
            return ['ok' => false, 'locked' => true, 'retry_after' => aegis_mfa_lock_remaining($ip, $now)];
        }

        $code = preg_replace('/\s+/', '', $code);
        $ok = false;

        // route by shape, a TOTP can never be compared against a backup hash or vice versa
        if (aegis_mfa_looks_like_backup_code($code)) {
            $ok = aegis_mfa_consume_backup_code($user, $code);
        } else {
            $secret = aegis_mfa_get_secret($user);
            if ($secret !== null) {
                $step = aegis_totp_verify_step($secret, $code, 1);
                if ($step !== false) {
                    // replay guard: reject a code from a step already used
                    if ($step > aegis_mfa_get_last_step($user)) {
                        aegis_mfa_set_last_step($user, $step);
                        $ok = true;
                    }
                // valid code but already consumed -> fail
                }
            }
        }

        if ($ok) {
            aegis_mfa_clear_failures($ip);
            aegis_mfa_mark_verified($user);
            @syslog(LOG_INFO, "aegis-mfa: 2FA success for $user from $ip");
            return ['ok' => true];
        }

        $remaining = aegis_mfa_record_failure($ip, $user, $now);
        @syslog(LOG_WARNING, "aegis-mfa: 2FA failure for $user from $ip");
        if ($remaining <= 0) {
            return ['ok' => false, 'locked' => true, 'retry_after' => aegis_mfa_lock_remaining($ip, $now)];
        }
        return ['ok' => false, 'remaining' => $remaining];

    } catch (\Throwable $e) {
        // verification errors do NOT grant access. the gate is fail-open, the verifier is fail-safe
        @error_log('aegis-mfa verify: ' . $e->getMessage());
        return ['ok' => false, 'remaining' => 1];
    }
}

// seconds until an active lock expires, 0 if not locked
function aegis_mfa_lock_remaining(string $ip, ?int $now = null): int {
    $d = aegis_mfa_read_json(aegis_mfa_lockout_path());
    $until = (int)($d['failures'][$ip]['locked_until'] ?? 0);
    return max(0, $until - ($now ?? time()));
}

// backup codes: bcrypt-hashed in secrets.json, single-use
// shape test: 10 hex chars in two groups, dash optional. a 6-digit TOTP never matches
function aegis_mfa_looks_like_backup_code(string $code): bool {
    return (bool)preg_match('/^[0-9a-f]{5}-?[0-9a-f]{5}$/i', $code);
}

// N codes, returns [plain, hashed]. plain is shown once, only hashed persists
function aegis_mfa_generate_backup_codes(int $n = 10): array {
    $plain = []; $hashed = [];
    for ($i = 0; $i < $n; $i++) {
        $raw = bin2hex(random_bytes(5));                 // 10 hex chars
        $fmt = substr($raw, 0, 5) . '-' . substr($raw, 5);
        $plain[]  = $fmt;
        $hashed[] = password_hash($raw, PASSWORD_DEFAULT);
    }
    return [$plain, $hashed];
}

// verify and consume: compare against every unused hash, mark the match
function aegis_mfa_consume_backup_code(string $user, string $code): bool {
    $norm = strtolower(str_replace('-', '', $code));
    if (!preg_match('/^[0-9a-f]{10}$/', $norm)) return false;

    $matchedIndex = -1;
    // slow bcrypt compares outside the lock, take it only to record consumption
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $codes = $sec['users'][$user]['backup_codes'] ?? [];
    $used  = $sec['users'][$user]['backup_codes_used'] ?? [];
    if (!is_array($codes)) return false;
    foreach ($codes as $idx => $hash) {
        if (in_array($idx, $used, true)) continue;
        if (is_string($hash) && password_verify($norm, $hash)) { $matchedIndex = $idx; break; }
    }
    if ($matchedIndex < 0) return false;

    // re-check still unused under the lock, guards the same code submitted twice concurrently
    $consumed = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $matchedIndex, &$consumed) {
            $u = $s['users'][$user] ?? null;
            if (!is_array($u)) return $s;
            $used = $u['backup_codes_used'] ?? [];
            if (in_array($matchedIndex, $used, true)) return $s;   // already used
            $used[] = $matchedIndex;
            $s['users'][$user]['backup_codes_used'] = $used;
            $consumed = true;
            return $s;
        });
    return $consumed;
}

// unused count for the settings UI
function aegis_mfa_backup_codes_remaining(string $user): int {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $codes = $sec['users'][$user]['backup_codes'] ?? [];
    $used  = $sec['users'][$user]['backup_codes_used'] ?? [];
    if (!is_array($codes)) return 0;
    return max(0, count($codes) - count(is_array($used) ? $used : []));
}
