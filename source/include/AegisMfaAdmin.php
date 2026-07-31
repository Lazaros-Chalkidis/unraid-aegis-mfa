<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaGate.php';

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
        $users[] = [
            'name'             => $u,
            'status'           => $status,
            'seen'             => $seen,
            'backup_remaining' => aegis_mfa_backup_codes_remaining($u),
            'enrolled_at'      => $rec['enrolled_at'] ?? null,
            'grace_until'      => $rec['grace_until'] ?? null,
        ];
    }

    $lockedIps = 0; $failuresToday = 0;
    foreach (($lock['failures'] ?? []) as $ip => $e) {
        if ((int)($e['locked_until'] ?? 0) > $now) $lockedIps++;
        if ((int)($e['last_at'] ?? 0) > $now - 86400) $failuresToday += (int)($e['count'] ?? 0);
    }

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
    ];
}
