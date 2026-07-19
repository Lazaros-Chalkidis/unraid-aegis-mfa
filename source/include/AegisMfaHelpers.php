<?php
/*
 * Aegis MFA for Unraid - shared helpers
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Design rule: helpers never throw. Every failure returns null/false
 * so the gate stays fail-open. All functions carry the aegis_mfa_
 * prefix, same collision reasoning as the TOTP module.
 */

// persistent state on flash: config, secrets. survives reboot
function aegis_mfa_flash(): string {
    return defined('AEGIS_MFA_FLASH_DIR') ? AEGIS_MFA_FLASH_DIR : '/boot/config/plugins/aegis.mfa';
}

// ephemeral state in RAM: lockout counters. cleared on reboot by design, keeps brute force off the USB flash
function aegis_mfa_state(): string {
    return defined('AEGIS_MFA_STATE_DIR') ? AEGIS_MFA_STATE_DIR : '/var/local/aegis.mfa';
}

// read under shared lock. array on success, null otherwise
function aegis_mfa_read_json(string $path): ?array {
    if (!is_file($path)) return null;
    $fp = @fopen($path, 'r');
    if ($fp === false) return null;
    $data = null;
    if (flock($fp, LOCK_SH)) {
        $raw = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        $dec = json_decode((string)$raw, true);
        if (is_array($dec)) $data = $dec;
    }
    fclose($fp);
    return $data;
}

// exclusive read-modify-write, LOCK_EX on the same inode, so counter increments are never lost
function aegis_mfa_update_json(string $path, callable $fn, int $mode = 0600): bool {
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return false;
    $fp = @fopen($path, 'c+');
    if ($fp === false) return false;
    $ok = false;
    if (flock($fp, LOCK_EX)) {
        $raw = stream_get_contents($fp);
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) $data = [];
        $new = $fn($data);
        if (is_array($new)) {
            $json = json_encode($new, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if ($json !== false && ftruncate($fp, 0) && rewind($fp)) {
                $ok = fwrite($fp, $json) !== false;
                fflush($fp);
            }
        }
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    if ($ok) @chmod($path, $mode);   // best effort, no-op on FAT
    return $ok;
}

// overwrite with fixed content, same locking
function aegis_mfa_write_json(string $path, array $data, int $mode = 0600): bool {
    return aegis_mfa_update_json($path, function ($old) use ($data) { return $data; }, $mode);
}

// config with defaults deep-merged, a partial or old config.json never leaves a key missing. one disk read per request
function aegis_mfa_config(bool $reload = false): array {
    static $cache = null;
    if ($cache !== null && !$reload) return $cache;
    $defaults = [
        'version'           => 1,
        'enabled'           => false,
        'enforce_after'     => 0,
        'trust_lan'         => [],
        'trusted_proxies'   => [],
        'lockout'           => ['threshold' => 5, 'window_seconds' => 300, 'lock_seconds' => 900],
        'grace_period_days' => 7,
    ];
    $file = aegis_mfa_read_json(aegis_mfa_flash() . '/config.json');
    if (!is_array($file)) $file = [];
    $cfg = array_replace($defaults, $file);
    $cfg['lockout'] = array_replace($defaults['lockout'],
        is_array($file['lockout'] ?? null) ? $file['lockout'] : []);
    foreach (['trust_lan', 'trusted_proxies'] as $k) {
        if (!is_array($cfg[$k])) $cfg[$k] = [];
    }
    return $cache = $cfg;
}

// USB rescue: a flag file on flash bypasses MFA entirely
function aegis_mfa_disabled_by_flag(): bool {
    return is_file(aegis_mfa_flash() . '/DISABLE.flag');
}

function aegis_mfa_enabled(): bool {
    if (aegis_mfa_disabled_by_flag()) return false;
    return !empty(aegis_mfa_config()['enabled']);
}

// dry-run window: before enforce_after, failures log but do not block
function aegis_mfa_enforcing(?int $now = null): bool {
    return ($now ?? time()) >= (int)(aegis_mfa_config()['enforce_after'] ?? 0);
}

// binary cidr match, v4 and v6 in one path. bare IPs allowed
function aegis_mfa_cidr_match(string $ip, string $cidr): bool {
    $ip_bin = @inet_pton($ip);
    if ($ip_bin === false) return false;
    if (strpos($cidr, '/') === false) {
        $sub_bin = @inet_pton($cidr);
        return $sub_bin !== false && $ip_bin === $sub_bin;
    }
    list($subnet, $bits) = explode('/', $cidr, 2);
    $sub_bin = @inet_pton($subnet);
    if ($sub_bin === false || !ctype_digit($bits)) return false;
    if (strlen($ip_bin) !== strlen($sub_bin)) return false;   // family mismatch
    $bits = (int)$bits;
    if ($bits < 0 || $bits > strlen($ip_bin) * 8) return false;
    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($sub_bin, 0, $bytes)) return false;
    if ($rem > 0) {
        $mask = 0xff << (8 - $rem) & 0xff;
        if ((ord($ip_bin[$bytes]) & $mask) !== (ord($sub_bin[$bytes]) & $mask)) return false;
    }
    return true;
}

function aegis_mfa_ip_trusted(string $ip, ?array $cidrs = null): bool {
    $cidrs = $cidrs ?? aegis_mfa_config()['trust_lan'];
    foreach ($cidrs as $cidr) {
        if (is_string($cidr) && aegis_mfa_cidr_match($ip, $cidr)) return true;
    }
    return false;
}

// client IP. XFF honoured only when REMOTE_ADDR is a configured proxy, otherwise trivially spoofable
function aegis_mfa_client_ip(): string {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $proxies = aegis_mfa_config()['trusted_proxies'];
    if ($remote !== '' && $proxies && in_array($remote, $proxies, true)) {
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff !== '') {
            $first = trim(explode(',', $xff)[0]);
            if (filter_var($first, FILTER_VALIDATE_IP)) return $first;
        }
    }
    return $remote;
}

function aegis_mfa_session_name(): string {
    return ini_get('session.name') ?: 'PHPSESSID';
}

// start a session if none is active, a no-op when unraid already opened one
function aegis_mfa_session_ensure(): bool {
    if (session_status() === PHP_SESSION_ACTIVE) return true;
    if (session_status() === PHP_SESSION_DISABLED) return false;
    return @session_start();
}

// confirmed unraid 7.3.1 keys: unraid_login (timestamp), unraid_user (name)
function aegis_mfa_has_unraid_session(): bool {
    return !empty($_SESSION['unraid_login']) && !empty($_SESSION['unraid_user']);
}

function aegis_mfa_current_user(): string {
    return is_string($_SESSION['unraid_user'] ?? null) ? $_SESSION['unraid_user'] : '';
}

// mark this session as passed. our own namespace, unraid keys never touched
function aegis_mfa_mark_verified(?string $user = null): bool {
    if (!aegis_mfa_session_ensure()) return false;
    $user = $user ?? aegis_mfa_current_user();
    if ($user === '') return false;
    $_SESSION['aegis_mfa'] = ['verified' => true, 'user' => $user, 'at' => time()];
    return true;
}

// the verified flag belongs to the current user, a user switch never inherits it
function aegis_mfa_session_verified(): bool {
    $m = $_SESSION['aegis_mfa'] ?? null;
    if (!is_array($m) || empty($m['verified'])) return false;
    $user = aegis_mfa_current_user();
    return $user !== '' && ($m['user'] ?? '') === $user;
}

// the session was offered the prompt and moved on. grace and dry-run prompt once per session, not per request.
// Lives next to verified so a fresh login clears both, merging keeps an existing verified intact
function aegis_mfa_mark_nudged(?string $user = null): bool {
    if (!aegis_mfa_session_ensure()) return false;
    $user = $user ?? aegis_mfa_current_user();
    if ($user === '') return false;
    $m = $_SESSION['aegis_mfa'] ?? [];
    if (!is_array($m) || ($m['user'] ?? '') !== $user) $m = ['user' => $user];
    $m['nudged'] = time();
    $_SESSION['aegis_mfa'] = $m;
    return true;
}

// same user-switch guard as the verified flag
function aegis_mfa_session_nudged(): bool {
    $m = $_SESSION['aegis_mfa'] ?? null;
    if (!is_array($m) || empty($m['nudged'])) return false;
    $user = aegis_mfa_current_user();
    return $user !== '' && ($m['user'] ?? '') === $user;
}

// top-level page navigations only. bouncing assets or pollers turns every subresource 401 into a /login redirect
// and floods the authlimit zone. Fetch Metadata when present, Accept otherwise, anything ambiguous passes (fail open)
function aegis_mfa_request_is_navigation(): bool {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') return false;
    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null;
    if ($dest !== null) return $dest === 'document';
    return strpos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') !== false;
}

// webGUI-capable users, mirroring how .login.php authenticates: in passwd, with a usable shadow hash.
// $getent lets the tests inject fixture lines
function aegis_mfa_unraid_users(?callable $getent = null): array {
    $getent = $getent ?? function (string $db): array {
        $out = [];
        @exec('/usr/bin/getent ' . escapeshellarg($db) . ' 2>/dev/null', $out);
        return $out;
    };
    // shadow: user -> hash
    $hashes = [];
    foreach ($getent('shadow') as $line) {
        $f = explode(':', $line);
        if (count($f) < 2) continue;
        $hashes[$f[0]] = $f[1];
    }
    $users = [];
    foreach ($getent('passwd') as $line) {
        $f = explode(':', $line);
        if (count($f) < 3) continue;
        $name = $f[0];
        $uid  = (int)$f[2];
        // root plus uid >= 1000 with a real hash. lock markers (*, !, !!) and empty fields cannot web-login
        if ($name !== 'root' && $uid < 1000) continue;
        $h = $hashes[$name] ?? '';
        if ($h === '' || $h[0] === '*' || $h[0] === '!') continue;
        $users[] = $name;
    }
    return $users;
}

// reconcile secrets.json against the live user list: new users become pending with a grace deadline,
// removed users are dropped, existing entries untouched. idempotent, runs at boot and from cron
function aegis_mfa_sync_users(?callable $getent = null, ?int $now = null): array {
    $now   = $now ?? time();
    $live  = aegis_mfa_unraid_users($getent);
    // an empty list means the read failed, not no users: root always exists. acting on it would wipe every enrolment
    if (!$live) return ['added' => [], 'removed' => [], 'skipped' => 'no_live_users'];
    // a list without root is also a bad read (shadow not loaded yet at boot). add-only then, never delete
    $trustRemovals = in_array('root', $live, true);
    $grace = (int)aegis_mfa_config()['grace_period_days'] * 86400;
    $added = []; $removed = []; $kept = [];
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($live, $now, $grace, $trustRemovals, &$added, &$removed, &$kept) {
            if (!isset($sec['users']) || !is_array($sec['users'])) $sec['users'] = [];
            $liveSet = array_flip($live);
            foreach ($live as $u) {
                if (!isset($sec['users'][$u])) {
                    $sec['users'][$u] = ['status' => 'pending', 'grace_until' => $now + $grace];
                    $added[] = $u;
                }
            }
            foreach (array_keys($sec['users']) as $u) {
                if (isset($liveSet[$u])) continue;
                // an enrolled user has real setup effort behind the secret, one bad snapshot must never delete that.
                // Only prune accounts that never finished enrolment, and only from a snapshot that includes root
                $status = $sec['users'][$u]['status'] ?? '';
                if ($status === 'enrolled' || !$trustRemovals) { $kept[] = $u; continue; }
                unset($sec['users'][$u]);
                $removed[] = $u;
            }
            if (!isset($sec['version'])) $sec['version'] = 1;
            return $sec;
        });
    $res = ['added' => $added, 'removed' => $removed, 'live' => count($live)];
    if (!$trustRemovals) $res['skipped'] = 'no_root_in_list';
    if ($kept)           $res['kept']    = $kept;
    return $res;
}

// 'enrolled' | 'pending' | 'locked' (grace expired) | 'none'
function aegis_mfa_user_status(string $user, ?int $now = null): string {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $u = $sec['users'][$user] ?? null;
    if (!is_array($u)) return 'none';
    $status = $u['status'] ?? '';
    if ($status === 'enrolled') return 'enrolled';
    if ($status === 'pending') {
        $grace = (int)($u['grace_until'] ?? 0);
        if ($grace > 0 && ($now ?? time()) > $grace) return 'locked';
        return 'pending';
    }
    return 'none';
}

function aegis_mfa_get_secret(string $user): ?string {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $s = $sec['users'][$user]['secret'] ?? null;
    return is_string($s) && $s !== '' ? $s : null;
}

// replay protection state: highest TOTP step already consumed
function aegis_mfa_get_last_step(string $user): int {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    return (int)($sec['users'][$user]['last_step'] ?? 0);
}

function aegis_mfa_set_last_step(string $user, int $step): bool {
    return aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $step) {
            if (!isset($sec['users'][$user]) || !is_array($sec['users'][$user])) return $sec;
            $cur = (int)($sec['users'][$user]['last_step'] ?? 0);
            if ($step > $cur) $sec['users'][$user]['last_step'] = $step;
            return $sec;
        });
}

// lockout is RAM-backed and resets on reboot, fail-open
function aegis_mfa_lockout_path(): string {
    return aegis_mfa_state() . '/lockout.json';
}

function aegis_mfa_is_locked(string $ip, ?int $now = null): bool {
    $d = aegis_mfa_read_json(aegis_mfa_lockout_path());
    $e = $d['failures'][$ip] ?? null;
    return is_array($e) && (int)($e['locked_until'] ?? 0) > ($now ?? time());
}

// count a failed attempt, returns attempts remaining, 0 = locked now
function aegis_mfa_record_failure(string $ip, string $user, ?int $now = null): int {
    $lk = aegis_mfa_config()['lockout'];
    $now = $now ?? time();
    $remaining = 0;
    aegis_mfa_update_json(aegis_mfa_lockout_path(),
        function ($d) use ($ip, $user, $now, $lk, &$remaining) {
            $e = $d['failures'][$ip] ?? null;
            if (!is_array($e) || $now - (int)($e['first_at'] ?? 0) > $lk['window_seconds']) {
                $e = ['count' => 0, 'first_at' => $now];
            }
            $e['count']++;
            $e['last_at']  = $now;
            $e['username'] = $user;
            if ($e['count'] >= $lk['threshold']) {
                $e['locked_until'] = $now + $lk['lock_seconds'];
            }
            $remaining = max(0, $lk['threshold'] - $e['count']);
            $d['failures'][$ip] = $e;
            return $d;
        });
    return $remaining;
}

function aegis_mfa_clear_failures(string $ip): bool {
    return aegis_mfa_update_json(aegis_mfa_lockout_path(),
        function ($d) use ($ip) {
            unset($d['failures'][$ip]);
            return $d;
        });
}

// cron cleanup: drop entries with no active lock and an expired window
function aegis_mfa_prune_lockouts(?int $now = null): bool {
    $lk = aegis_mfa_config()['lockout'];
    $now = $now ?? time();
    return aegis_mfa_update_json(aegis_mfa_lockout_path(),
        function ($d) use ($now, $lk) {
            foreach (($d['failures'] ?? []) as $ip => $e) {
                $locked = (int)($e['locked_until'] ?? 0) > $now;
                $fresh  = $now - (int)($e['last_at'] ?? 0) <= $lk['window_seconds'];
                if (!$locked && !$fresh) unset($d['failures'][$ip]);
            }
            return $d;
        });
}
