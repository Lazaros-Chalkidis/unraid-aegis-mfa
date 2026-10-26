<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaGate.php';
require_once __DIR__ . '/AegisMfaWebauthn.php';

function aegis_mfa_set_config_key(string $key, $value): bool {
    $ok = aegis_mfa_update_json(aegis_mfa_flash() . '/config.json',
        function ($c) use ($key, $value) { $c[$key] = $value; return $c; });
    aegis_mfa_config(true);
    return $ok;
}

// writes config only, the page controller calls reconcile afterwards so the patches follow the setting
function aegis_mfa_set_enabled(bool $on): bool {
    return aegis_mfa_set_config_key('enabled', $on);
}

function aegis_mfa_enforce_now(?int $now = null): bool {
    return aegis_mfa_set_config_key('enforce_after', $now ?? time());
}

function aegis_mfa_start_dry_run(int $hours = 24, ?int $now = null): bool {
    $now = $now ?? time();
    return aegis_mfa_set_config_key('enforce_after', $now + max(0, $hours) * 3600);
}

function aegis_mfa_set_grace_days(int $days): bool {
    return aegis_mfa_set_config_key('grace_period_days', max(0, $days));
}

function aegis_mfa_set_lockout_history(bool $on): bool {
    return aegis_mfa_set_config_key('lockout_history', $on);
}

function aegis_mfa_valid_cidr(string $c): bool {
    $c = trim($c);
    if ($c === '') return false;
    if (strpos($c, '/') === false) return @inet_pton($c) !== false;
    list($ip, $bits) = explode('/', $c, 2);
    $bin = @inet_pton($ip);
    if ($bin === false || $bits === '' || !ctype_digit($bits)) return false;
    $b = (int)$bits;
    return $b >= 0 && $b <= strlen($bin) * 8;
}

function aegis_mfa_set_trust_lan(array $cidrs): array {
    $accepted = []; $rejected = [];
    foreach ($cidrs as $c) {
        $c = trim((string)$c);
        if ($c === '') continue;
        if (aegis_mfa_valid_cidr($c)) $accepted[] = $c;
        else $rejected[] = $c;
    }
    $accepted = array_values(array_unique($accepted));
    $ok = aegis_mfa_set_config_key('trust_lan', $accepted);
    return ['ok' => $ok, 'accepted' => $accepted, 'rejected' => $rejected];
}

function aegis_mfa_set_trusted_proxies(array $ips): array {
    $accepted = []; $rejected = [];
    foreach ($ips as $ip) {
        $ip = trim((string)$ip);
        if ($ip === '') continue;
        if (@inet_pton($ip) !== false) $accepted[] = $ip;
        else $rejected[] = $ip;
    }
    $accepted = array_values(array_unique($accepted));
    $ok = aegis_mfa_set_config_key('trusted_proxies', $accepted);
    return ['ok' => $ok, 'accepted' => $accepted, 'rejected' => $rejected];
}

// drops the secret and puts the account back in grace
function aegis_mfa_reset_user(string $user, bool $requireReenroll = true, ?int $now = null): bool {
    $now = $now ?? time();
    return aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $requireReenroll, $now) {
            if (!isset($sec['users'][$user])) return $sec;
            if ($requireReenroll) {
                $grace = (int)aegis_mfa_config()['grace_period_days'] * 86400;
                $sec['users'][$user] = ['status' => 'pending', 'grace_until' => $now + $grace];
            } else {
                unset($sec['users'][$user]);
            }
            return $sec;
        });
}

// the new codes sit in the session until one is typed back, so a half-finished page leaves the old ones working
function aegis_mfa_begin_backup_regen(string $user): ?array {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    if (($sec['users'][$user]['status'] ?? '') !== 'enrolled') return null;
    if (!aegis_mfa_session_ensure()) return null;
    list($plain, $hashed) = aegis_mfa_generate_backup_codes(10);
    $_SESSION['aegis_mfa_regen'] = [
        'user'    => $user,
        'plain'   => $plain,
        'hashed'  => $hashed,
        'started' => time(),
    ];
    return $plain;
}

function aegis_mfa_regen_state(?int $now = null): ?array {
    $r = $_SESSION['aegis_mfa_regen'] ?? null;
    if (!is_array($r) || empty($r['plain'])) return null;

    // never show one account's codes to another, whatever unraid allows to log in later
    $user = aegis_mfa_current_user();
    if ($user === '' || ($r['user'] ?? '') !== $user) return null;

    // the session outlives the plugin: a reset, or a full uninstall and reinstall, leaves this
    // sitting here offering codes for an enrolment that no longer exists
    $stale = ($now ?? time()) - (int)($r['started'] ?? 0) > 1800;
    if ($stale || aegis_mfa_user_status($user) !== 'enrolled') {
        unset($_SESSION['aegis_mfa_regen']);
        return null;
    }
    return $r;
}

function aegis_mfa_cancel_backup_regen(): void {
    unset($_SESSION['aegis_mfa_regen']);
}

// the typed code is spent, same as at enrolment: it has been through a browser form
function aegis_mfa_commit_backup_regen(string $confirm): array {
    $r = aegis_mfa_regen_state();
    if ($r === null) return ['ok' => false, 'reason' => 'no_regen'];

    $norm = strtolower(str_replace('-', '', $confirm));
    $used = -1;
    foreach ($r['plain'] as $i => $c) {
        if (strtolower(str_replace('-', '', $c)) === $norm) { $used = $i; break; }
    }
    if ($used < 0) return ['ok' => false, 'reason' => 'bad_confirm'];

    $user = $r['user'];
    $wrote = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $r, $used, &$wrote) {
            if (($s['users'][$user]['status'] ?? '') !== 'enrolled') return $s;
            $s['users'][$user]['backup_codes']      = $r['hashed'];
            $s['users'][$user]['backup_codes_used'] = [$used];
            $wrote = true;
            return $s;
        });
    if (!$wrote) return ['ok' => false, 'reason' => 'not_enrolled'];

    unset($_SESSION['aegis_mfa_regen']);
    return ['ok' => true];
}

function aegis_mfa_set_webauthn_rp_origin(string $origin): array {
    $origin = trim($origin);
    if ($origin === '') {
        aegis_mfa_set_config_key('webauthn_rp_origin', '');
        return ['ok' => true];
    }
    if (!aegis_mfa_webauthn_valid_origin($origin)) return ['ok' => false, 'reason' => 'invalid'];
    aegis_mfa_set_config_key('webauthn_rp_origin', rtrim($origin, '/'));
    return ['ok' => true];
}

function aegis_mfa_set_webauthn_assume_https(bool $on): bool {
    return aegis_mfa_set_config_key('webauthn_assume_https', $on);
}

// begins adding TOTP to an already-enrolled user (Settings "Add an authenticator app"), same additive shape as aegis_mfa_add_passkey below
function aegis_mfa_begin_totp_add(string $user): ?array {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    if (($sec['users'][$user]['status'] ?? '') !== 'enrolled') return null;
    if (!aegis_mfa_session_ensure()) return null;
    $secret = aegis_totp_generate_secret();
    $_SESSION['aegis_mfa_totp_add'] = ['user' => $user, 'secret' => $secret, 'started' => time()];
    return ['secret' => $secret, 'uri' => aegis_totp_uri($secret, $user . '@' . aegis_mfa_server_name(), 'Aegis MFA')];
}

// never hand back one account's pending secret to another session, same guard as aegis_mfa_regen_state()
function aegis_mfa_totp_add_state(?int $now = null): ?array {
    $r = $_SESSION['aegis_mfa_totp_add'] ?? null;
    if (!is_array($r) || empty($r['secret'])) return null;
    $user = aegis_mfa_current_user();
    if ($user === '' || ($r['user'] ?? '') !== $user) return null;
    $stale = ($now ?? time()) - (int)($r['started'] ?? 0) > 1800;
    if ($stale || aegis_mfa_user_status($user) !== 'enrolled') {
        unset($_SESSION['aegis_mfa_totp_add']);
        return null;
    }
    return $r;
}

function aegis_mfa_cancel_totp_add(): void {
    unset($_SESSION['aegis_mfa_totp_add']);
}

// verified the same way initial TOTP enrolment is, merged in without touching passkeys or backup codes
function aegis_mfa_commit_totp_add(string $code): array {
    $r = aegis_mfa_totp_add_state();
    if ($r === null) return ['ok' => false, 'reason' => 'no_totp_add'];
    if (!aegis_totp_verify($r['secret'], $code, 1)) return ['ok' => false, 'reason' => 'bad_code'];

    $user = $r['user'];
    $wrote = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $r, &$wrote) {
            if (($s['users'][$user]['status'] ?? '') !== 'enrolled') return $s;
            $s['users'][$user]['secret']    = $r['secret'];
            $s['users'][$user]['algorithm'] = 'SHA1';
            $s['users'][$user]['digits']    = 6;
            $s['users'][$user]['period']    = 30;
            $s['users'][$user]['last_step'] = 0;
            $wrote = true;
            return $s;
        });
    if (!$wrote) return ['ok' => false, 'reason' => 'not_enrolled'];

    unset($_SESSION['aegis_mfa_totp_add']);
    return ['ok' => true];
}

// commits an extra passkey for an *already enrolled* user (Settings "Add a passkey"), distinct from the initial-enrolment path in AegisMfaEnroll.php
function aegis_mfa_add_passkey(string $user, array $credentialResponse, string $expectedOrigin, string $label = 'Passkey'): array {
    $challenge = aegis_webauthn_take_challenge($user, 'register');
    if ($challenge === null) return ['ok' => false, 'reason' => 'challenge_expired'];

    $r = aegis_webauthn_verify_registration($credentialResponse, $challenge, $expectedOrigin, aegis_mfa_webauthn_rp_id());
    if (!($r['ok'] ?? false)) return $r;

    $label = trim($label) !== '' ? substr(trim($label), 0, 60) : 'Passkey';
    $entry = [
        'id'           => aegis_webauthn_b64url_encode($r['credential_id']),
        'public_key'   => $r['public_key'],
        'sign_count'   => $r['sign_count'],
        'created_at'   => time(),
        'last_used_at' => null,
        'label'        => $label,
    ];
    $added = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $entry, &$added) {
            if (($s['users'][$user]['status'] ?? '') !== 'enrolled') return $s;
            $list = $s['users'][$user]['passkeys'] ?? [];
            if (!is_array($list)) $list = [];
            $list[] = $entry;
            $s['users'][$user]['passkeys'] = $list;
            $added = true;
            return $s;
        });
    return $added ? ['ok' => true] : ['ok' => false, 'reason' => 'not_enrolled'];
}

// refuses to strip a user's last second factor (no TOTP, only this passkey) - starting over has its own path, reset_user
function aegis_mfa_remove_passkey(string $user, string $credentialIdB64Url): array {
    // decided under the same lock as the write, a reset in another tab must not slip between the two.
    // a refusal returns null so the flash is not rewritten for nothing
    $reason = 'not_found';
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $credentialIdB64Url, &$reason) {
            $rec = $s['users'][$user] ?? null;
            if (!is_array($rec) || ($rec['status'] ?? '') !== 'enrolled') { $reason = 'not_enrolled'; return null; }
            $list = is_array($rec['passkeys'] ?? null) ? $rec['passkeys'] : [];
            $new = array_values(array_filter($list, function ($pk) use ($credentialIdB64Url) {
                return !(is_array($pk) && ($pk['id'] ?? '') === $credentialIdB64Url);
            }));
            if (count($new) === count($list)) { $reason = 'not_found'; return null; }
            if (empty($rec['secret']) && count($new) === 0) { $reason = 'last_factor'; return null; }
            $s['users'][$user]['passkeys'] = $new;
            $reason = null;
            return $s;
        });
    return ['ok' => $reason === null, 'reason' => $reason];
}

function aegis_mfa_rename_passkey(string $user, string $credentialIdB64Url, string $label): bool {
    $label = trim($label);
    if ($label === '') $label = 'Passkey';
    if (strlen($label) > 60) $label = substr($label, 0, 60);
    $wrote = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $credentialIdB64Url, $label, &$wrote) {
            if (($s['users'][$user]['status'] ?? '') !== 'enrolled') return null;
            $list = $s['users'][$user]['passkeys'] ?? null;
            if (!is_array($list)) return null;
            foreach ($list as $i => $pk) {
                if (is_array($pk) && ($pk['id'] ?? '') === $credentialIdB64Url) {
                    $s['users'][$user]['passkeys'][$i]['label'] = $label;
                    $wrote = true;
                    break;
                }
            }
            return $wrote ? $s : null;
        });
    return $wrote;
}

function aegis_mfa_admin_summary(?callable $getent = null, ?int $now = null): array {
    $now = $now ?? time();
    $cfg = aegis_mfa_config(true);
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json') ?? ['users' => []];
    $lock = aegis_mfa_read_json(aegis_mfa_lockout_path()) ?? ['failures' => []];

    $users = []; $enrolled = 0; $pending = 0; $seenCount = 0;
    foreach (aegis_mfa_unraid_users($getent) as $u) {
        $status = aegis_mfa_user_status($u, $now);
        $rec    = $sec['users'][$u] ?? [];
        $seen   = (int)($rec['seen_at'] ?? 0) > 0 || $status === 'enrolled';

        // share users never reach the webGUI login, so they are not part of the count
        if ($seen) {
            $seenCount++;
            if ($status === 'enrolled') $enrolled++;
            if ($status === 'pending' || $status === 'locked') $pending++;
        }
        $userPasskeys = is_array($rec['passkeys'] ?? null) ? $rec['passkeys'] : [];
        $users[] = [
            'name'             => $u,
            'status'           => $status,
            'seen'             => $seen,
            'backup_remaining' => aegis_mfa_backup_codes_remaining($u),
            'enrolled_at'      => $rec['enrolled_at'] ?? null,
            'grace_until'      => $rec['grace_until'] ?? null,
            'has_totp'         => !empty($rec['secret']),
            'passkeys'         => $userPasskeys,
        ];
    }

    $lockedIps = 0;
    foreach (($lock['failures'] ?? []) as $ip => $e) {
        if ((int)($e['locked_until'] ?? 0) > $now) $lockedIps++;
    }
    $failuresToday = aegis_mfa_failures_today($now);

    return [
        'enabled'        => aegis_mfa_enabled(),
        'enforcing'      => aegis_mfa_enforcing($now),
        'enforce_after'  => (int)$cfg['enforce_after'],
        'dry_run'        => aegis_mfa_enabled() && !aegis_mfa_enforcing($now),
        'trust_lan'      => $cfg['trust_lan'],

        // being exempt without knowing it is the worst state to leave an admin in
        'client_ip'      => aegis_mfa_client_ip(),
        'client_trusted' => aegis_mfa_client_ip() !== '' && aegis_mfa_ip_trusted(aegis_mfa_client_ip()),
        'trusted_proxies'=> $cfg['trusted_proxies'],
        'grace_days'     => (int)$cfg['grace_period_days'],
        'enrolled'       => $enrolled,
        'pending'        => $pending,
        'total_users'    => $seenCount,
        'listed_users'   => count($users),
        'locked_ips'     => $lockedIps,
        'failures_today' => $failuresToday,
        'history_on'     => !empty($cfg['lockout_history']),
        'history'        => aegis_mfa_lockout_history($now),
        'users'          => $users,

        'webauthn_configured'     => aegis_mfa_webauthn_configured(),
        'webauthn_available'      => aegis_mfa_webauthn_available(),
        'webauthn_rp_origin'      => aegis_mfa_webauthn_rp_origin(),
        'webauthn_current_origin' => aegis_mfa_webauthn_current_origin(),
        'webauthn_assume_https'   => !empty($cfg['webauthn_assume_https']),
    ];
}
