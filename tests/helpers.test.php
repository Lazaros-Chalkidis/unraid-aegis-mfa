<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// locking, config merge, user sync, lockouts. run: php tests/helpers.test.php

if (($argv[1] ?? '') === 'worker') {
    define('AEGIS_MFA_FLASH_DIR', $argv[2]);
    define('AEGIS_MFA_STATE_DIR', $argv[2]);
    require __DIR__ . '/../source/include/AegisMfaHelpers.php';
    $n = (int)$argv[3];
    for ($i = 0; $i < $n; $i++) {
        aegis_mfa_update_json($argv[2] . '/counter.json',
            function ($d) { $d['n'] = ($d['n'] ?? 0) + 1; return $d; });
    }
    exit(0);
}

$work = sys_get_temp_dir() . '/aegis-mfa-test-' . getmypid();
@mkdir($work, 0700, true);
define('AEGIS_MFA_FLASH_DIR', $work . '/flash');
define('AEGIS_MFA_STATE_DIR', $work . '/state');
ini_set('session.save_path', $work);

require __DIR__ . '/../source/include/AegisMfaHelpers.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

$f = AEGIS_MFA_FLASH_DIR . '/t.json';
t('read missing',      aegis_mfa_read_json($f) === null);
t('write ok',          aegis_mfa_write_json($f, ['a' => 1]) === true);
t('read back',         aegis_mfa_read_json($f) === ['a' => 1]);
t('update ok',         aegis_mfa_update_json($f, function ($d) { $d['a']++; return $d; }) === true);
t('update applied',    aegis_mfa_read_json($f)['a'] === 2);
file_put_contents($f, '{broken json');
t('read corrupt',      aegis_mfa_read_json($f) === null);
t('update heals',      aegis_mfa_update_json($f, function ($d) { $d['x'] = 9; return $d; }) === true);
t('healed content',    aegis_mfa_read_json($f) === ['x' => 9]);
t('write bad dir',     aegis_mfa_write_json('/proc/nope/x.json', ['a' => 1]) === false);
$perm = fileperms($f) & 0777;
t('mode 0600',         $perm === 0600);

$cdir = $work . '/conc';
@mkdir($cdir, 0700, true);
$cmd = PHP_BINARY . ' ' . escapeshellarg(__FILE__) . ' worker ' . escapeshellarg($cdir) . ' 200';
$p1 = popen($cmd, 'r');
$p2 = popen($cmd, 'r');
pclose($p1);
pclose($p2);
$counter = aegis_mfa_read_json($cdir . '/counter.json');
t('flock no lost updates (400)', ($counter['n'] ?? 0) === 400);

$cfg = aegis_mfa_config(true);
t('cfg default disabled',  $cfg['enabled'] === false);
t('cfg default lockout',   $cfg['lockout']['threshold'] === 5);
t('cfg default grace',     $cfg['grace_period_days'] === 2);
t('cfg default history',   $cfg['lockout_history'] === true);

// the shipped file and the code defaults have to agree, or a fresh install differs from an upgrade
$shipped = json_decode((string)@file_get_contents(__DIR__ . '/../source/config.default.json'), true);
t('shipped grace matches',   ($shipped['grace_period_days'] ?? null) === $cfg['grace_period_days']);
t('shipped history matches', ($shipped['lockout_history'] ?? null) === $cfg['lockout_history']);
t('shipped lockout matches', ($shipped['lockout'] ?? null) === $cfg['lockout']);
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'lockout' => ['threshold' => 3]]);
$cfg = aegis_mfa_config(true);
t('cfg file enabled',      $cfg['enabled'] === true);
t('cfg partial merge',     $cfg['lockout']['threshold'] === 3);
t('cfg merge keeps rest',  $cfg['lockout']['window_seconds'] === 300);
t('cfg trust_lan array',   $cfg['trust_lan'] === []);
t('enabled true',          aegis_mfa_enabled() === true);
touch(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');
t('DISABLE.flag wins',     aegis_mfa_enabled() === false);
unlink(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');
t('flag removed',          aegis_mfa_enabled() === true);

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'enforce_after' => 1000]);
aegis_mfa_config(true);
t('dry-run before',        aegis_mfa_enforcing(999) === false);
t('enforcing at',          aegis_mfa_enforcing(1000) === true);
t('enforcing after',       aegis_mfa_enforcing(2000) === true);

t('v4 in /24',        aegis_mfa_cidr_match('10.0.0.5', '10.0.0.0/24') === true);
t('v4 out /24',       aegis_mfa_cidr_match('10.0.1.5', '10.0.0.0/24') === false);
t('v4 edge .255',     aegis_mfa_cidr_match('10.0.0.255', '10.0.0.0/24') === true);
t('v4 /32 hit',       aegis_mfa_cidr_match('10.0.0.4', '10.0.0.4/32') === true);
t('v4 /32 miss',      aegis_mfa_cidr_match('10.0.0.5', '10.0.0.4/32') === false);
t('v4 /25 low',       aegis_mfa_cidr_match('192.168.1.127', '192.168.1.0/25') === true);
t('v4 /25 high',      aegis_mfa_cidr_match('192.168.1.128', '192.168.1.0/25') === false);
t('v4 /31 pair',      aegis_mfa_cidr_match('192.168.1.1', '192.168.1.0/31') === true);
t('v4 /0 all',        aegis_mfa_cidr_match('8.8.8.8', '0.0.0.0/0') === true);
t('v4 bare hit',      aegis_mfa_cidr_match('10.0.0.4', '10.0.0.4') === true);
t('v4 bare miss',     aegis_mfa_cidr_match('10.0.0.5', '10.0.0.4') === false);
t('v6 loop /128',     aegis_mfa_cidr_match('::1', '::1/128') === true);
t('v6 expanded',      aegis_mfa_cidr_match('0:0:0:0:0:0:0:1', '::1/128') === true);
t('v6 /64 in',        aegis_mfa_cidr_match('fd00::abcd', 'fd00::/64') === true);
t('v6 /64 out',       aegis_mfa_cidr_match('fd00:0:0:1::1', 'fd00::/64') === false);
t('v6 /0 all',        aegis_mfa_cidr_match('2001:db8::1', '::/0') === true);
t('family mismatch',  aegis_mfa_cidr_match('10.0.0.1', '::1/128') === false);
t('family mismatch2', aegis_mfa_cidr_match('::1', '10.0.0.0/24') === false);
t('bad ip',           aegis_mfa_cidr_match('banana', '10.0.0.0/24') === false);
t('bad cidr',         aegis_mfa_cidr_match('10.0.0.1', 'banana/24') === false);
t('bad bits',         aegis_mfa_cidr_match('10.0.0.1', '10.0.0.0/xx') === false);
t('bits too big',     aegis_mfa_cidr_match('10.0.0.1', '10.0.0.0/33') === false);

t('trusted hit',   aegis_mfa_ip_trusted('10.0.0.9', ['192.168.0.0/16', '10.0.0.0/24']) === true);
t('trusted miss',  aegis_mfa_ip_trusted('8.8.8.8', ['192.168.0.0/16', '10.0.0.0/24']) === false);
t('trusted empty', aegis_mfa_ip_trusted('10.0.0.9', []) === false);
t('trusted junk',  aegis_mfa_ip_trusted('10.0.0.9', [42, null, '10.0.0.0/24']) === true);

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => true]);
aegis_mfa_config(true);
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1, 10.0.0.1';
t('xff ignored by default', aegis_mfa_client_ip() === '203.0.113.7');
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'trusted_proxies' => ['203.0.113.7']]);
aegis_mfa_config(true);
t('xff honoured from proxy', aegis_mfa_client_ip() === '198.51.100.1');
$_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-an-ip';
t('xff invalid falls back',  aegis_mfa_client_ip() === '203.0.113.7');
$_SERVER['REMOTE_ADDR'] = '10.0.0.99';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1';
t('xff from non-proxy ignored', aegis_mfa_client_ip() === '10.0.0.99');
unset($_SERVER['HTTP_X_FORWARDED_FOR']);

t('session ensure',      aegis_mfa_session_ensure() === true);
t('session name',        aegis_mfa_session_name() === (ini_get('session.name') ?: 'PHPSESSID'));
t('no unraid session',   aegis_mfa_has_unraid_session() === false);
t('current user empty',  aegis_mfa_current_user() === '');
t('verified no session', aegis_mfa_session_verified() === false);
t('mark fails no user',  aegis_mfa_mark_verified() === false);

$_SESSION['unraid_login'] = time();
$_SESSION['unraid_user']  = 'root';
t('unraid session ok',   aegis_mfa_has_unraid_session() === true);
t('current user root',   aegis_mfa_current_user() === 'root');
t('not verified yet',    aegis_mfa_session_verified() === false);
t('mark verified',       aegis_mfa_mark_verified() === true);
t('verified now',        aegis_mfa_session_verified() === true);
t('namespace intact',    $_SESSION['aegis_mfa']['user'] === 'root');
t('unraid keys intact',  $_SESSION['unraid_user'] === 'root');

$_SESSION['unraid_user'] = 'lazaros';
t('switch invalidates',  aegis_mfa_session_verified() === false);
t('mark explicit user',  aegis_mfa_mark_verified('lazaros') === true);
t('verified as new',     aegis_mfa_session_verified() === true);

unset($_SESSION['aegis_mfa']);
$_SESSION['unraid_user'] = '';
t('nudge fails no user',  aegis_mfa_mark_nudged() === false);
$_SESSION['unraid_user'] = 'root';
t('not nudged yet',       aegis_mfa_session_nudged() === false);
t('mark nudged',          aegis_mfa_mark_nudged() === true);
t('nudged now',           aegis_mfa_session_nudged() === true);
t('nudge not verified',   aegis_mfa_session_verified() === false);

t('verify after nudge',   aegis_mfa_mark_verified('root') === true);
t('re-nudge keeps verify', aegis_mfa_mark_nudged('root') === true
                           && aegis_mfa_session_verified() === true
                           && aegis_mfa_session_nudged() === true);

$_SESSION['unraid_user'] = 'lazaros';
t('switch drops nudge',   aegis_mfa_session_nudged() === false);
t('nudge fresh user',     aegis_mfa_mark_nudged('lazaros') === true
                           && aegis_mfa_session_nudged() === true
                           && aegis_mfa_session_verified() === false);

$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
unset($_SERVER['HTTP_ACCEPT']);
t('nav: get document',     aegis_mfa_request_is_navigation() === true);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';
t('nav: xhr not nav',      aegis_mfa_request_is_navigation() === false);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'iframe';
t('nav: iframe not nav',   aegis_mfa_request_is_navigation() === false);
unset($_SERVER['HTTP_SEC_FETCH_DEST']);
$_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml;q=0.9';
t('nav: legacy html get',  aegis_mfa_request_is_navigation() === true);
$_SERVER['HTTP_ACCEPT'] = 'application/json';
t('nav: legacy json get',  aegis_mfa_request_is_navigation() === false);
unset($_SERVER['HTTP_ACCEPT']);
t('nav: bare get not nav', aegis_mfa_request_is_navigation() === false);
$_SERVER['REQUEST_METHOD'] = 'POST';
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
t('nav: post not nav',     aegis_mfa_request_is_navigation() === false);
unset($_SERVER['REQUEST_METHOD'], $_SERVER['HTTP_SEC_FETCH_DEST']);

$sec = [
    'version' => 1,
    'users' => [
        'root'    => ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'last_step' => 100],
        'media'   => ['status' => 'pending', 'grace_until' => 2000],
        'backup'  => ['status' => 'pending', 'grace_until' => 500],
        'nograce' => ['status' => 'pending'],
        'weird'   => ['status' => 'banana'],
    ],
];
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', $sec);

t('status enrolled',       aegis_mfa_user_status('root', 1000) === 'enrolled');
t('status pending',        aegis_mfa_user_status('media', 1000) === 'pending');
t('status grace expired',  aegis_mfa_user_status('backup', 1000) === 'locked');
t('status no grace set',   aegis_mfa_user_status('nograce', 1000) === 'pending');
t('status unknown user',   aegis_mfa_user_status('ghost', 1000) === 'none');
t('status bad value',      aegis_mfa_user_status('weird', 1000) === 'none');

t('secret found',          aegis_mfa_get_secret('root') === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
t('secret missing',        aegis_mfa_get_secret('media') === null);
t('secret unknown',        aegis_mfa_get_secret('ghost') === null);

t('last step read',        aegis_mfa_get_last_step('root') === 100);
t('last step default',     aegis_mfa_get_last_step('media') === 0);
t('last step advance',     aegis_mfa_set_last_step('root', 150) === true);
t('last step advanced',    aegis_mfa_get_last_step('root') === 150);
t('last step replay false', aegis_mfa_set_last_step('root', 150) === false);
t('last step regress false', aegis_mfa_set_last_step('root', 120) === false);
t('last step no regress',  aegis_mfa_get_last_step('root') === 150);
t('last step ghost false', aegis_mfa_set_last_step('ghost', 99) === false);
$ghost = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json')['users']['ghost'] ?? null;
t('last step ghost noop',  $ghost === null);

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'lockout' => ['threshold' => 3, 'window_seconds' => 100, 'lock_seconds' => 60]]);
aegis_mfa_config(true);

$ip = '203.0.113.42';
t('not locked initially',  aegis_mfa_is_locked($ip, 1000) === false);
t('fail 1 remaining 2',    aegis_mfa_record_failure($ip, 'root', 1000) === 2);
t('fail 2 remaining 1',    aegis_mfa_record_failure($ip, 'root', 1010) === 1);
t('still not locked',      aegis_mfa_is_locked($ip, 1010) === false);
t('fail 3 locks',          aegis_mfa_record_failure($ip, 'root', 1020) === 0);
t('locked now',            aegis_mfa_is_locked($ip, 1020) === true);
t('locked within period',  aegis_mfa_is_locked($ip, 1079) === true);
t('unlocks after period',  aegis_mfa_is_locked($ip, 1081) === false);

$ip2 = '198.51.100.7';
aegis_mfa_record_failure($ip2, 'media', 1000);
aegis_mfa_record_failure($ip2, 'media', 1010);
t('window resets count',   aegis_mfa_record_failure($ip2, 'media', 1200) === 2);

aegis_mfa_clear_failures($ip);
t('cleared unlocks',       aegis_mfa_is_locked($ip, 1020) === false);

aegis_mfa_record_failure('192.0.2.1', 'x', 1000);
aegis_mfa_record_failure('192.0.2.2', 'x', 5000);
for ($i = 0; $i < 3; $i++) aegis_mfa_record_failure('192.0.2.3', 'x', 5000);
aegis_mfa_prune_lockouts(5050);
$d = aegis_mfa_read_json(aegis_mfa_lockout_path());
t('prune drops stale',     !isset($d['failures']['192.0.2.1']));
t('prune keeps fresh',     isset($d['failures']['192.0.2.2']));
t('prune keeps locked',    isset($d['failures']['192.0.2.3']));

// the day counter is what the Failed today card shows, so a success or a prune must not touch it
aegis_mfa_write_json(aegis_mfa_lockout_path(), []);
$day = 1_800_000_000;
aegis_mfa_record_failure('10.0.0.3', 'root', $day);
aegis_mfa_record_failure('10.0.0.3', 'root', $day + 20);
t('day counts failures',       aegis_mfa_failures_today($day + 30) === 2);
aegis_mfa_clear_failures('10.0.0.3');
t('day survives a success',    aegis_mfa_failures_today($day + 40) === 2);
aegis_mfa_record_failure('10.0.0.9', 'root', $day + 60);
aegis_mfa_prune_lockouts($day + 60 + 500);
t('day survives the prune',    aegis_mfa_failures_today($day + 60 + 501) === 3);
t('day reads zero tomorrow',   aegis_mfa_failures_today($day + 86400) === 0);
aegis_mfa_record_failure('10.0.0.9', 'root', $day + 86400);
t('day restarts on a new date', aegis_mfa_failures_today($day + 86400) === 1);
t('no day key reads zero',     (aegis_mfa_write_json(aegis_mfa_lockout_path(), ['failures' => []]) && aegis_mfa_failures_today($day) === 0));

$fixture = function (string $db): array {
    if ($db === 'passwd') return [
        'root:x:0:0::/root:/bin/bash',
        'bin:x:1:1:bin:/bin:/sbin/nologin',
        'nobody:x:99:99:nobody:/:/sbin/nologin',
        'lazaros:x:1000:100::/home/lazaros:/bin/bash',
        'media:x:1001:100::/home/media:/bin/false',
        'locked:x:1002:100::/home/locked:/bin/false',
        'nopass:x:1003:100::/home/nopass:/bin/false',
    ];
    if ($db === 'shadow') return [
        'root:$6$abc$realhashROOT:19000:0:99999:7:::',
        'bin:*:19000:0:99999:7:::',
        'nobody:!:19000:0:99999:7:::',
        'lazaros:$6$def$realhashLAZ:19000:0:99999:7:::',
        'media:$6$ghi$realhashMED:19000:0:99999:7:::',
        'locked:!$6$x$stillLocked:19000:0:99999:7:::',
        'nopass::19000:0:99999:7:::',
    ];
    return [];
};

$users = aegis_mfa_unraid_users($fixture);
sort($users);
t('enum includes root',    in_array('root', $users, true));
t('enum includes web u1',  in_array('lazaros', $users, true));
t('enum includes web u2',  in_array('media', $users, true));
t('enum excludes system',  !in_array('bin', $users, true) && !in_array('nobody', $users, true));
t('enum excludes locked',  !in_array('locked', $users, true));
t('enum excludes nopass',  !in_array('nopass', $users, true));
t('enum exact set',        $users === ['lazaros', 'media', 'root']);

@unlink(AEGIS_MFA_FLASH_DIR . '/secrets.json');
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'grace_period_days' => 7]);
aegis_mfa_config(true);
$r = aegis_mfa_sync_users($fixture, 1000);
sort($r['added']);
t('sync adds all',         $r['added'] === ['lazaros', 'media', 'root']);
t('sync removes none',     $r['removed'] === []);
t('sync reports live',     ($r['live'] ?? 0) === 3);
t('sync root pending',     aegis_mfa_user_status('root', 1000) === 'pending');
$secNow = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('sync grace set',        $secNow['users']['root']['grace_until'] === 1000 + 7 * 86400);

$r2 = aegis_mfa_sync_users($fixture, 2000);
t('sync idempotent',       $r2['added'] === [] && $r2['removed'] === []);

aegis_mfa_update_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', function ($s) {
    $s['users']['root'] = ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'];
    return $s;
});
aegis_mfa_sync_users($fixture, 3000);
t('sync keeps enrolled',   aegis_mfa_user_status('root', 3000) === 'enrolled');

$smaller = function (string $db) use ($fixture): array {
    return array_values(array_filter($fixture($db), fn($l) => strpos($l, 'media:') !== 0));
};
$r3 = aegis_mfa_sync_users($smaller, 4000);
t('sync drops removed',    $r3['removed'] === ['media']);
t('removed user gone',     aegis_mfa_user_status('media', 4000) === 'none');
t('other users survive',   aegis_mfa_user_status('root', 4000) === 'enrolled');

$empty = function (string $db): array { return []; };
$syncBefore = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
$rg = aegis_mfa_sync_users($empty, 5000);
t('sync empty read skipped',   ($rg['skipped'] ?? '') === 'no_live_users');
t('sync empty removed none',   $rg['removed'] === [] && $rg['added'] === []);
t('sync empty file untouched', aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === $syncBefore);
t('sync empty root survives',  aegis_mfa_user_status('root', 5000) === 'enrolled');

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root'  => ['status' => 'enrolled', 'secret' => 'S', 'backup_codes' => ['a'], 'backup_codes_used' => []],
    'ghost' => ['status' => 'pending', 'grace_until' => 9999999999],
]]);
$listNoRoot = function (string $db): array {

    if ($db === 'shadow') return ['alice:$6$x'];
    if ($db === 'passwd') return ['alice:x:1000:1000::/home/alice:/bin/bash'];
    return [];
};
$rr = aegis_mfa_sync_users($listNoRoot, 6000);
t('no-root list skips removals', ($rr['skipped'] ?? '') === 'no_root_in_list');
t('no-root list keeps enrolled root', aegis_mfa_user_status('root', 6000) === 'enrolled');
t('no-root list keeps pending ghost too', isset(aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json')['users']['ghost']));
t('no-root list still adds alice', in_array('alice', $rr['added'], true));

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root'    => ['status' => 'enrolled', 'secret' => 'S', 'backup_codes' => ['a'], 'backup_codes_used' => []],
    'oldpend' => ['status' => 'pending', 'grace_until' => 9999999999],
    'oldenr'  => ['status' => 'enrolled', 'secret' => 'T', 'backup_codes' => ['b'], 'backup_codes_used' => []],
]]);
$rootOnly = function (string $db): array {
    if ($db === 'shadow') return ['root:$6$h'];
    if ($db === 'passwd') return ['root:x:0:0::/root:/bin/bash'];
    return [];
};
$rp = aegis_mfa_sync_users($rootOnly, 7000);
t('trusted list prunes stale pending', in_array('oldpend', $rp['removed'], true));
t('trusted list spares absent enrolled', aegis_mfa_user_status('oldenr', 7000) === 'enrolled');
t('trusted list reports kept', in_array('oldenr', $rp['kept'] ?? [], true));
t('trusted list keeps root', aegis_mfa_user_status('root', 7000) === 'enrolled');

// lockout history
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['lockout' => ['threshold' => 3, 'window_seconds' => 300, 'lock_seconds' => 900],
     'lockout_history' => true]);
aegis_mfa_config(true);
@unlink(aegis_mfa_lockout_path());
@unlink(aegis_mfa_history_path());

t('history default is on', aegis_mfa_config(true)['lockout_history'] === true);

for ($i = 0; $i < 2; $i++) aegis_mfa_record_failure('10.0.0.9', 'root', 1000);
t('no history below threshold', aegis_mfa_history_ram() === []);
aegis_mfa_record_failure('10.0.0.9', 'root', 1000);
$hr = aegis_mfa_history_ram();
t('lock writes one ram row', count($hr) === 1 && isset($hr['10.0.0.9']));
t('ram row keeps the account', ($hr['10.0.0.9']['username'] ?? '') === 'root');
t('lock does not touch the flash', !is_file(aegis_mfa_history_path()));

$hist = aegis_mfa_lockout_history(1000);
t('history reports remaining', $hist[0]['remaining'] === 900);
t('history reports the count', $hist[0]['count'] === 3);
t('history expires with the lock', aegis_mfa_lockout_history(9000)[0]['remaining'] === 0);

t('flush writes the snapshot', aegis_mfa_flush_lockout_history() === true);
t('snapshot landed on the flash', count(aegis_mfa_history_disk()) === 1);
t('second flush is a no-op', aegis_mfa_flush_lockout_history() === false);

for ($i = 0; $i < 3; $i++) aegis_mfa_record_failure('10.0.0.9', 'root', 5000);
t('relock updates the same row', count(aegis_mfa_history_ram()) === 1);
t('relock moves locked_at', aegis_mfa_history_ram()['10.0.0.9']['locked_at'] === 5000);
t('changed set flushes again', aegis_mfa_flush_lockout_history() === true);

aegis_mfa_update_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    function ($c) { $c['lockout_history'] = false; return $c; });
aegis_mfa_config(true);
for ($i = 0; $i < 3; $i++) aegis_mfa_record_failure('10.0.0.11', 'root', 6000);
t('flush refused when off', aegis_mfa_flush_lockout_history() === false);
t('ram still records when off', count(aegis_mfa_history_ram()) === 2);
t('history visible when off', count(aegis_mfa_lockout_history(6000)) === 2);
aegis_mfa_update_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    function ($c) { $c['lockout_history'] = true; return $c; });
aegis_mfa_config(true);

t('forget rejects junk', aegis_mfa_forget_lockout('not-an-ip') === false);
t('forget rejects a path', aegis_mfa_forget_lockout('../../etc/passwd') === false);
aegis_mfa_forget_lockout('10.0.0.11');
t('forget drops the row', !isset(aegis_mfa_history_ram()['10.0.0.11']));
t('forget clears the counter', !aegis_mfa_is_locked('10.0.0.11', 6000));

for ($i = 0; $i < 3; $i++) aegis_mfa_record_failure('10.0.0.12', 'root', 9000);
aegis_mfa_flush_lockout_history();
t('clear keeps a live lock', aegis_mfa_clear_lockout_history(9100) === 1);
$left = aegis_mfa_lockout_history(9100);
t('clear left the live row', count($left) === 1 && $left[0]['ip'] === '10.0.0.12');
t('clear pruned the flash copy', count(aegis_mfa_history_disk()) === 1);

$many = [];
for ($i = 0; $i < 130; $i++) $many["10.1.0.$i"] = ['locked_at' => 1000 + $i, 'locked_until' => 0];
$capped = aegis_mfa_history_trim($many);
t('cap holds at 100', count($capped) === 100);
t('cap keeps the newest', isset($capped['10.1.0.129']) && !isset($capped['10.1.0.0']));
t('trim sorts newest first', array_key_first($capped) === '10.1.0.129');

// failures map is bounded too, or a flood grows the tmpfs file without limit
@unlink(aegis_mfa_lockout_path());
aegis_mfa_update_json(aegis_mfa_lockout_path(), function ($d) {
    for ($i = 0; $i < aegis_mfa_failures_max(); $i++) {
        $d['failures']["10.2." . intdiv($i, 256) . "." . ($i % 256)] =
            ['count' => 1, 'first_at' => 100, 'last_at' => 100 + $i];
    }
    return $d;
});
aegis_mfa_record_failure('10.9.9.9', 'root', 99999);
$fl = aegis_mfa_read_json(aegis_mfa_lockout_path())['failures'];
t('failures capped', count($fl) === aegis_mfa_failures_max());
t('failures keep the newest', isset($fl['10.9.9.9']));
t('failures drop the oldest', !isset($fl['10.2.0.0']));

t('server name never empty', aegis_mfa_server_name() !== '');

// the challenge page renders for browsers asking for a page, never for a poller
$keep = $_SERVER;
foreach ([
    ['document', null, 'GET',  true,  'navigation'],
    ['document', null, 'POST', true,  'form post'],
    ['empty',    null, 'GET',  false, 'xhr'],
    ['script',   null, 'GET',  false, 'script tag'],
    ['image',    null, 'GET',  false, 'image'],
    [null, 'text/html,application/xhtml+xml', 'GET', true,  'old browser, html accept'],
    [null, 'application/json',                'GET', false, 'old client, json accept'],
    [null, '',                                'GET', true,  'no headers at all'],
] as [$dest, $accept, $method, $want, $label]) {
    $_SERVER = ['REQUEST_METHOD' => $method];
    if ($dest !== null)   $_SERVER['HTTP_SEC_FETCH_DEST'] = $dest;
    if ($accept !== null) $_SERVER['HTTP_ACCEPT'] = $accept;
    t("wants page: $label", aegis_mfa_request_wants_page() === $want);
}
$_SERVER = $keep;

// the history file lives on the flash and can come back truncated or half-written
foreach ([
    'scalar rows'   => ['version' => 1, 'entries' => ['1.1.1.1' => 'x', '2.2.2.2' => 'y']],
    'entries scalar'=> ['version' => 1, 'entries' => 'nonsense'],
    'no entries'    => ['version' => 1],
    'null row'      => ['version' => 1, 'entries' => ['1.1.1.1' => null]],
] as $name => $bad) {
    aegis_mfa_write_json(aegis_mfa_history_path(), $bad);
    $threw = false;
    try {
        aegis_mfa_lockout_history(1000);
        aegis_mfa_flush_lockout_history();
        aegis_mfa_clear_lockout_history(2000);
    } catch (\Throwable $e) { $threw = true; }
    t("corrupt history survives: $name", $threw === false);
}
file_put_contents(aegis_mfa_history_path(), '{"entries":{"1.1.1.1":');
t('truncated history reads empty', aegis_mfa_history_disk() === []);
@unlink(aegis_mfa_history_path());

// theme: emhttp global wins, then the user file, then the shipped defaults
file_put_contents($cdir . '/dynamix.cfg', "[display]\ntheme=\"azure\"\n");
file_put_contents($cdir . '/default.cfg', "[display]\ntheme=\"white\"\n");
define('AEGIS_MFA_DYNAMIX_CFG', $cdir . '/dynamix.cfg');
define('AEGIS_MFA_DYNAMIX_DEFAULT', $cdir . '/default.cfg');

t('theme from user file', aegis_mfa_theme() === 'azure');
$GLOBALS['display'] = ['theme' => 'black'];
t('emhttp global wins',  aegis_mfa_theme() === 'black');
$GLOBALS['display'] = ['theme' => 'nonsense'];
t('junk global ignored', aegis_mfa_theme() === 'azure');
unset($GLOBALS['display']);

file_put_contents($cdir . '/dynamix.cfg', "[display]\nsomething=\"else\"\n");
t('falls back to defaults', aegis_mfa_theme() === 'white');
@unlink($cdir . '/dynamix.cfg');
t('missing user file ok',   aegis_mfa_theme() === 'white');
@unlink($cdir . '/default.cfg');
t('no file falls back light', aegis_mfa_theme() === 'white');

t('white is light', aegis_mfa_theme_is_light('white') === true);
t('azure is light', aegis_mfa_theme_is_light('azure') === true);
t('black is dark',  aegis_mfa_theme_is_light('black') === false);
t('gray is dark',   aegis_mfa_theme_is_light('gray') === false);

echo "\nhelpers.test.php: {$pass} passed, {$fail} failed\n";

foreach (glob("$work/flash/*") as $g) @unlink($g);
foreach (glob("$work/state/*") as $g) @unlink($g);
foreach (glob("$work/conc/*") as $g) @unlink($g);
foreach (glob("$work/sess_*") as $g) @unlink($g);
@rmdir("$work/flash"); @rmdir("$work/state"); @rmdir("$work/conc"); @rmdir($work);
exit($fail === 0 ? 0 : 1);
