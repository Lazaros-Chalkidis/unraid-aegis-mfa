<?php
/*
 * Aegis MFA for Unraid - admin settings actions + summary
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Backs the settings page. These functions only touch config/secrets;
 * toggling "enabled" writes config, and the PAGE controller is responsible
 * for calling aegis_mfa_reconcile_patches() afterwards so the patches follow
 * the setting. Keeping that dependency in the controller (not here) means
 * this file never needs the installer.
 */

require_once __DIR__ . '/AegisMfaGate.php';

function aegis_mfa_set_config_key(string $key, $value): bool {
    $ok = aegis_mfa_update_json(aegis_mfa_flash() . '/config.json',
        function ($c) use ($key, $value) { $c[$key] = $value; return $c; });
    aegis_mfa_config(true);   // drop the static cache so the next read is fresh
    return $ok;
}

// caller must run aegis_mfa_reconcile_patches() after this
function aegis_mfa_set_enabled(bool $on): bool {
    return aegis_mfa_set_config_key('enabled', $on);
}

function aegis_mfa_enforce_now(?int $now = null): bool {
    return aegis_mfa_set_config_key('enforce_after', $now ?? time());
}

// begin a dry-run window: enabled but non-enforcing for $hours
function aegis_mfa_start_dry_run(int $hours = 24, ?int $now = null): bool {
    $now = $now ?? time();
    return aegis_mfa_set_config_key('enforce_after', $now + max(0, $hours) * 3600);
}

function aegis_mfa_set_grace_days(int $days): bool {
    return aegis_mfa_set_config_key('grace_period_days', max(0, $days));
}

// valid when inet_pton parses the address and the prefix fits the family width
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

// validate a list, keep the good ones, report the rest
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

// reset a user's 2FA. requireReenroll puts them back in a fresh grace window, false removes them entirely
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

// fresh backup codes for an enrolled user, plain codes shown once
function aegis_mfa_regenerate_backup_codes(string $user): ?array {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    if (($sec['users'][$user]['status'] ?? '') !== 'enrolled') return null;
    list($plain, $hashed) = aegis_mfa_generate_backup_codes(10);
    $ok = aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($s) use ($user, $hashed) {
            $s['users'][$user]['backup_codes'] = $hashed;
            $s['users'][$user]['backup_codes_used'] = [];
            return $s;
        });
    return $ok ? $plain : null;
}

// everything the settings page needs in one call. getent is injectable so this is testable
function aegis_mfa_admin_summary(?callable $getent = null, ?int $now = null): array {
    $now = $now ?? time();
    $cfg = aegis_mfa_config(true);
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json') ?? ['users' => []];
    $lock = aegis_mfa_read_json(aegis_mfa_lockout_path()) ?? ['failures' => []];

    $users = []; $enrolled = 0; $pending = 0;
    foreach (aegis_mfa_unraid_users($getent) as $u) {
        $status = aegis_mfa_user_status($u, $now);
        if ($status === 'enrolled') $enrolled++;
        if ($status === 'pending' || $status === 'locked') $pending++;
        $rec = $sec['users'][$u] ?? [];
        $users[] = [
            'name'             => $u,
            'status'           => $status,
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
        'trusted_proxies'=> $cfg['trusted_proxies'],
        'grace_days'     => (int)$cfg['grace_period_days'],
        'enrolled'       => $enrolled,
        'pending'        => $pending,
        'total_users'    => count($users),
        'locked_ips'     => $lockedIps,
        'failures_today' => $failuresToday,
        'users'          => $users,
    ];
}
