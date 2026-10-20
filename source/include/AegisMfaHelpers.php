<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

function aegis_mfa_flash(): string {
    return defined('AEGIS_MFA_FLASH_DIR') ? AEGIS_MFA_FLASH_DIR : '/boot/config/plugins/aegis.mfa';
}

function aegis_mfa_state(): string {
    return defined('AEGIS_MFA_STATE_DIR') ? AEGIS_MFA_STATE_DIR : '/var/local/aegis.mfa';
}

function aegis_mfa_var_ini(): array {
    static $v = null;
    if ($v === null) {
        $path = defined('AEGIS_MFA_VAR_INI') ? AEGIS_MFA_VAR_INI : '/usr/local/emhttp/state/var.ini';
        $v = @parse_ini_file($path) ?: [];
    }
    return $v;
}

// not from HTTP_HOST, the caller sets that and it lands in the user's authenticator app
function aegis_mfa_server_name(): string {
    $name = trim((string)(aegis_mfa_var_ini()['NAME'] ?? ''));
    return $name !== '' ? $name : (gethostname() ?: 'Unraid');
}

// recorded, not guessed from uid or shell: only accounts that turn up here can use 2FA
function aegis_mfa_seen_webgui(string $user): bool {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $u = $sec['users'][$user] ?? null;
    if (!is_array($u)) return false;

    // enrolling means going through the wizard behind a password login, so it counts on its own.
    // without this an account enrolled before seen_at existed reads as having no webGUI access
    return (int)($u['seen_at'] ?? 0) > 0 || ($u['status'] ?? '') === 'enrolled';
}

function aegis_mfa_mark_seen(string $user, ?int $now = null): bool {
    if (!preg_match('/^[a-z_][a-z0-9._-]{0,31}$/i', $user)) return false;
    if (aegis_mfa_seen_webgui($user)) return false;
    $now = $now ?? time();
    $wrote = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $now, &$wrote) {
            if (!isset($sec['users']) || !is_array($sec['users'])) $sec['users'] = [];

            // the account can turn up before the first sync, status is left for sync to fill in
            if (!isset($sec['users'][$user]) || !is_array($sec['users'][$user])) {
                $sec['users'][$user] = [];
            }
            if ((int)($sec['users'][$user]['seen_at'] ?? 0) > 0) return $sec;
            $sec['users'][$user]['seen_at'] = $now;
            $wrote = true;
            return $sec;
        });
    return $wrote;
}

// dynamix.cfg only exists once Display settings are touched, and defaulting to black paints white on white
function aegis_mfa_theme(): string {
    $known = ['black', 'white', 'azure', 'gray'];

    // inside an emhttp page $display is already the merged user + default config
    $t = $GLOBALS['display']['theme'] ?? '';
    if (is_string($t) && in_array($t, $known, true)) return $t;

    $files = [
        defined('AEGIS_MFA_DYNAMIX_CFG') ? AEGIS_MFA_DYNAMIX_CFG
            : '/boot/config/plugins/dynamix/dynamix.cfg',
        defined('AEGIS_MFA_DYNAMIX_DEFAULT') ? AEGIS_MFA_DYNAMIX_DEFAULT
            : '/usr/local/emhttp/plugins/dynamix/default.cfg',
    ];
    foreach ($files as $f) {
        $cfg = @parse_ini_file($f, true);
        $v   = is_array($cfg) ? ($cfg['display']['theme'] ?? '') : '';
        if (is_string($v) && in_array($v, $known, true)) return $v;
    }
    return 'white';
}

function aegis_mfa_theme_is_light(string $theme): bool {
    return in_array($theme, ['white', 'azure'], true);
}

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

// read-modify-write under LOCK_EX on the same inode, so concurrent counter bumps are never lost
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
    if ($ok) @chmod($path, $mode);
    return $ok;
}

function aegis_mfa_write_json(string $path, array $data, int $mode = 0600): bool {
    return aegis_mfa_update_json($path, function ($old) use ($data) { return $data; }, $mode);
}

// defaults deep-merged, so a partial or older config.json never leaves a key missing
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
        'lockout_history'   => true,
        'grace_period_days' => 2,
        'webauthn_rp_origin'=> '',
        'webauthn_assume_https' => false,
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

// USB rescue: a flag file on the flash bypasses MFA entirely
function aegis_mfa_disabled_by_flag(): bool {
    return is_file(aegis_mfa_flash() . '/DISABLE.flag');
}

function aegis_mfa_enabled(): bool {
    if (aegis_mfa_disabled_by_flag()) return false;
    return !empty(aegis_mfa_config()['enabled']);
}

function aegis_mfa_enforcing(?int $now = null): bool {
    return ($now ?? time()) >= (int)(aegis_mfa_config()['enforce_after'] ?? 0);
}

// scheme+host of the configured passkey origin, "" until an admin sets one
function aegis_mfa_webauthn_rp_origin(): string {
    $o = trim((string)(aegis_mfa_config()['webauthn_rp_origin'] ?? ''));
    return $o;
}

function aegis_mfa_webauthn_configured(): bool {
    return aegis_mfa_webauthn_rp_origin() !== '';
}

// the WebAuthn rp.id: hostname only, no scheme, no port
function aegis_mfa_webauthn_rp_id(): string {
    $host = parse_url(aegis_mfa_webauthn_rp_origin(), PHP_URL_HOST);
    return is_string($host) ? $host : '';
}

// scheme+host of the request actually being served right now
// a TLS-terminating reverse proxy (NPM, Traefik, a Cloudflare Tunnel) leaves $_SERVER['HTTPS'] unset even on a real https:// request - this is the admin saying so
// UI gate only, never the security check: verification always checks the origin clientDataJSON itself reports
function aegis_mfa_webauthn_current_origin(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || !empty(aegis_mfa_config()['webauthn_assume_https']);
    $host = (string)($_SERVER['HTTP_HOST'] ?? '');
    if ($host === '') return '';
    return ($https ? 'https://' : 'http://') . $host;
}

// gates every passkey button in the UI, not itself a security boundary: verification always re-checks clientDataJSON.origin regardless
function aegis_mfa_webauthn_available(): bool {
    if (!aegis_mfa_webauthn_configured()) return false;
    $cur = aegis_mfa_webauthn_current_origin();
    return $cur !== '' && strcasecmp($cur, aegis_mfa_webauthn_rp_origin()) === 0;
}

function aegis_mfa_webauthn_valid_origin(string $origin): bool {
    $origin = trim($origin);
    if (!preg_match('#^https://[^/\s]+$#i', $origin)) return false;
    $host = parse_url($origin, PHP_URL_HOST);
    return is_string($host) && $host !== '';
}

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
    if (strlen($ip_bin) !== strlen($sub_bin)) return false;
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

// XFF is honoured only when REMOTE_ADDR is a configured proxy, otherwise it is trivially spoofable
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

function aegis_mfa_session_ensure(): bool {
    if (session_status() === PHP_SESSION_ACTIVE) return true;
    if (session_status() === PHP_SESSION_DISABLED) return false;
    return @session_start();
}

function aegis_mfa_has_unraid_session(): bool {
    return !empty($_SESSION['unraid_login']) && !empty($_SESSION['unraid_user']);
}

function aegis_mfa_current_user(): string {
    return is_string($_SESSION['unraid_user'] ?? null) ? $_SESSION['unraid_user'] : '';
}

// our own session namespace, unraid's keys are never touched. the flag is bound to the user so a switch cannot inherit it
function aegis_mfa_mark_verified(?string $user = null): bool {
    if (!aegis_mfa_session_ensure()) return false;
    $user = $user ?? aegis_mfa_current_user();
    if ($user === '') return false;

    aegis_mfa_mark_seen($user);

    // no regenerate here, unraid's .login.php already does it with delete_old_session at password login
    $_SESSION['aegis_mfa'] = ['verified' => true, 'user' => $user, 'at' => time()];
    return true;
}

function aegis_mfa_session_verified(): bool {
    $m = $_SESSION['aegis_mfa'] ?? null;
    if (!is_array($m) || empty($m['verified'])) return false;
    $user = aegis_mfa_current_user();
    return $user !== '' && ($m['user'] ?? '') === $user;
}

function aegis_mfa_mark_nudged(?string $user = null): bool {
    if (!aegis_mfa_session_ensure()) return false;
    $user = $user ?? aegis_mfa_current_user();
    if ($user === '') return false;
    $m = $_SESSION['aegis_mfa'] ?? [];
    if (!is_array($m) || ($m['user'] ?? '') !== $user) $m = ['user' => $user];
    $m['nudged'] = time();
    $_SESSION['aegis_mfa'] = $m;
    aegis_mfa_mark_seen($user);
    return true;
}

function aegis_mfa_session_nudged(): bool {
    $m = $_SESSION['aegis_mfa'] ?? null;
    if (!is_array($m) || empty($m['nudged'])) return false;
    $user = aegis_mfa_current_user();
    return $user !== '' && ($m['user'] ?? '') === $user;
}

// only bounce top-level navigations. bouncing assets or pollers floods the nginx authlimit zone
function aegis_mfa_request_is_navigation(): bool {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') return false;
    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null;
    if ($dest !== null) return $dest === 'document';
    return strpos((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') !== false;
}

// a browser asking for a page, form posts included. anything else gets a bare 401 instead of
// our html, or unraid's own pollers end up parsing the challenge page as their data
function aegis_mfa_request_wants_page(): bool {
    $dest = $_SERVER['HTTP_SEC_FETCH_DEST'] ?? null;
    if ($dest !== null) return $dest === 'document';
    $accept = (string)($_SERVER['HTTP_ACCEPT'] ?? '');
    return $accept === '' || stripos($accept, 'text/html') !== false;
}

// webGUI-capable users only: in passwd, with a usable shadow hash. lock markers cannot log in
function aegis_mfa_unraid_users(?callable $getent = null): array {
    $getent = $getent ?? function (string $db): array {
        $out = [];
        @exec('/usr/bin/getent ' . escapeshellarg($db) . ' 2>/dev/null', $out);
        return $out;
    };

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

        if ($name !== 'root' && $uid < 1000) continue;
        $h = $hashes[$name] ?? '';
        if ($h === '' || $h[0] === '*' || $h[0] === '!') continue;
        $users[] = $name;
    }
    return $users;
}

// a snapshot missing root means a bad read, not no users. add-only then, or one bad read wipes every enrolment
function aegis_mfa_sync_users(?callable $getent = null, ?int $now = null): array {
    $now   = $now ?? time();
    $live  = aegis_mfa_unraid_users($getent);

    if (!$live) return ['added' => [], 'removed' => [], 'skipped' => 'no_live_users'];

    $trustRemovals = in_array('root', $live, true);
    $grace = (int)aegis_mfa_config()['grace_period_days'] * 86400;
    $added = []; $removed = []; $kept = [];
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($live, $now, $grace, $trustRemovals, &$added, &$removed, &$kept) {
            if (!isset($sec['users']) || !is_array($sec['users'])) $sec['users'] = [];
            $liveSet = array_flip($live);
            foreach ($live as $u) {
                if (!isset($sec['users'][$u]) || !is_array($sec['users'][$u])) {
                    $sec['users'][$u] = ['status' => 'pending', 'grace_until' => $now + $grace];
                    $added[] = $u;
                } elseif (($sec['users'][$u]['status'] ?? '') === '') {
                    // seen_at can be written before the first sync, keep it and fill in the rest
                    $sec['users'][$u]['status']      = 'pending';
                    $sec['users'][$u]['grace_until'] = $now + $grace;
                    $added[] = $u;
                }
            }
            foreach (array_keys($sec['users']) as $u) {
                if (isset($liveSet[$u])) continue;

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

function aegis_mfa_get_last_step(string $user): int {
    $sec = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    return (int)($sec['users'][$user]['last_step'] ?? 0);
}

// true only when this call advanced the step, so two parallel posts of one code cannot both pass
function aegis_mfa_set_last_step(string $user, int $step): bool {
    $advanced = false;
    aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
        function ($sec) use ($user, $step, &$advanced) {
            if (!isset($sec['users'][$user]) || !is_array($sec['users'][$user])) return $sec;
            $cur = (int)($sec['users'][$user]['last_step'] ?? 0);
            if ($step > $cur) {
                $sec['users'][$user]['last_step'] = $step;
                $advanced = true;
            }
            return $sec;
        });
    return $advanced;
}

// counters live in RAM on purpose, cleared on reboot, keeps brute force off the flash
function aegis_mfa_lockout_path(): string {
    return aegis_mfa_state() . '/lockout.json';
}

function aegis_mfa_is_locked(string $ip, ?int $now = null): bool {
    $d = aegis_mfa_read_json(aegis_mfa_lockout_path());
    $e = $d['failures'][$ip] ?? null;
    return is_array($e) && (int)($e['locked_until'] ?? 0) > ($now ?? time());
}

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
                if (!isset($d['history']) || !is_array($d['history'])) $d['history'] = [];
                $d['history'][$ip] = [
                    'count'        => $e['count'],
                    'locked_at'    => $now,
                    'locked_until' => $e['locked_until'],
                    'username'     => $user,
                ];
                $d['history'] = aegis_mfa_history_trim($d['history']);
            }
            $remaining = max(0, $lk['threshold'] - $e['count']);
            $d['failures'][$ip] = $e;
            if (count($d['failures']) > aegis_mfa_failures_max()) {
                $d['failures'] = aegis_mfa_trim_map($d['failures'], 'last_at', aegis_mfa_failures_max());
            }
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

// RAM alongside the counters, the flash copy is a snapshot the cron takes
function aegis_mfa_history_path(): string {
    return aegis_mfa_flash() . '/lockouts.json';
}

function aegis_mfa_history_max(): int {
    return 100;
}

// every failure rewrites the whole tmpfs file, so a flood from many addresses needs a ceiling
function aegis_mfa_failures_max(): int {
    return 500;
}

function aegis_mfa_trim_map(array $map, string $key, int $max): array {
    uasort($map, function ($a, $b) use ($key) {
        return (int)($b[$key] ?? 0) <=> (int)($a[$key] ?? 0);
    });
    return array_slice($map, 0, $max, true);
}

// one row per address, newest first, oldest dropped past the cap
function aegis_mfa_history_trim(array $entries): array {
    return aegis_mfa_trim_map($entries, 'locked_at', aegis_mfa_history_max());
}

function aegis_mfa_history_merge(array $base, array $add): array {
    foreach ($add as $ip => $e) {
        if (!is_string($ip) || !is_array($e)) continue;
        $have = $base[$ip] ?? null;
        if (!is_array($have) || (int)($e['locked_at'] ?? 0) >= (int)($have['locked_at'] ?? 0)) {
            $base[$ip] = $e;
        }
    }
    return aegis_mfa_history_trim($base);
}

function aegis_mfa_history_ram(): array {
    $d = aegis_mfa_read_json(aegis_mfa_lockout_path());
    $h = $d['history'] ?? null;
    return is_array($h) ? $h : [];
}

function aegis_mfa_history_disk(): array {
    $d = aegis_mfa_read_json(aegis_mfa_history_path());
    $e = $d['entries'] ?? null;
    return is_array($e) ? $e : [];
}

// called from the cron: writes only when the merged set differs from what is already on disk
function aegis_mfa_flush_lockout_history(): bool {
    if (empty(aegis_mfa_config()['lockout_history'])) return false;
    $ram = aegis_mfa_history_ram();
    if (!$ram) return false;
    $disk   = aegis_mfa_history_disk();
    $merged = aegis_mfa_history_merge($disk, $ram);
    if (json_encode($merged) === json_encode($disk)) return false;
    return aegis_mfa_write_json(aegis_mfa_history_path(), ['version' => 1, 'entries' => $merged]);
}

function aegis_mfa_lockout_history(?int $now = null): array {
    $now = $now ?? time();
    $all = aegis_mfa_history_merge(aegis_mfa_history_disk(), aegis_mfa_history_ram());
    $out = [];
    foreach ($all as $ip => $e) {
        if (!is_array($e)) continue;
        $out[] = [
            'ip'        => (string)$ip,
            'count'     => (int)($e['count'] ?? 0),
            'username'  => is_string($e['username'] ?? null) ? $e['username'] : '',
            'locked_at' => (int)($e['locked_at'] ?? 0),
            'remaining' => max(0, (int)($e['locked_until'] ?? 0) - $now),
        ];
    }
    return $out;
}

// drops the row and the live counter with it, so on an active lock this is the unlock
function aegis_mfa_forget_lockout(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) return false;
    aegis_mfa_update_json(aegis_mfa_lockout_path(), function ($d) use ($ip) {
        unset($d['failures'][$ip], $d['history'][$ip]);
        return $d;
    });
    if (!is_file(aegis_mfa_history_path())) return true;
    return aegis_mfa_update_json(aegis_mfa_history_path(), function ($d) use ($ip) {
        unset($d['entries'][$ip]);
        return $d;
    });
}

// expired rows only: an address still serving its lock stays visible, unlock it on its own row
function aegis_mfa_clear_lockout_history(?int $now = null): int {
    $now = $now ?? time();
    $gone = 0;
    $expired = function ($e) use ($now) {
        return !is_array($e) || (int)($e['locked_until'] ?? 0) <= $now;
    };
    aegis_mfa_update_json(aegis_mfa_lockout_path(), function ($d) use ($expired, &$gone) {
        if (!is_array($d['history'] ?? null)) return $d;
        foreach ($d['history'] as $ip => $e) {
            if ($expired($e)) { unset($d['history'][$ip]); $gone++; }
        }
        return $d;
    });
    if (is_file(aegis_mfa_history_path())) {
        aegis_mfa_update_json(aegis_mfa_history_path(), function ($d) use ($expired) {
            if (!is_array($d['entries'] ?? null)) return $d;
            foreach ($d['entries'] as $ip => $e) {
                if ($expired($e)) unset($d['entries'][$ip]);
            }
            return $d;
        });
    }
    return $gone;
}
