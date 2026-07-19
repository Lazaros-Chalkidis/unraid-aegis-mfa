<?php
/*
 * Aegis MFA - helpers test suite
 * run: php tests/helpers.test.php
 * exit 0 on full pass, 1 on any failure
 */

// worker mode: used by the concurrency test below. two of these run in
// parallel and hammer the same counter through aegis_mfa_update_json.
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

// json i/o
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

// concurrency: two workers, 200 increments each, no lost updates
$cdir = $work . '/conc';
@mkdir($cdir, 0700, true);
$cmd = PHP_BINARY . ' ' . escapeshellarg(__FILE__) . ' worker ' . escapeshellarg($cdir) . ' 200';
$p1 = popen($cmd, 'r');
$p2 = popen($cmd, 'r');
pclose($p1);
pclose($p2);
$counter = aegis_mfa_read_json($cdir . '/counter.json');
t('flock no lost updates (400)', ($counter['n'] ?? 0) === 400);

// config
$cfg = aegis_mfa_config(true);
t('cfg default disabled',  $cfg['enabled'] === false);
t('cfg default lockout',   $cfg['lockout']['threshold'] === 5);
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

// dry-run window
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'enforce_after' => 1000]);
aegis_mfa_config(true);
t('dry-run before',        aegis_mfa_enforcing(999) === false);
t('enforcing at',          aegis_mfa_enforcing(1000) === true);
t('enforcing after',       aegis_mfa_enforcing(2000) === true);

// cidr
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

// client ip / xff
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

// session
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

// user switch inside the same session must drop the verification
$_SESSION['unraid_user'] = 'lazaros';
t('switch invalidates',  aegis_mfa_session_verified() === false);
t('mark explicit user',  aegis_mfa_mark_verified('lazaros') === true);
t('verified as new',     aegis_mfa_session_verified() === true);

// nudge flag: same shape and same switch guard as the verified flag
unset($_SESSION['aegis_mfa']);
$_SESSION['unraid_user'] = '';
t('nudge fails no user',  aegis_mfa_mark_nudged() === false);
$_SESSION['unraid_user'] = 'root';
t('not nudged yet',       aegis_mfa_session_nudged() === false);
t('mark nudged',          aegis_mfa_mark_nudged() === true);
t('nudged now',           aegis_mfa_session_nudged() === true);
t('nudge not verified',   aegis_mfa_session_verified() === false);

// verifying after the nudge keeps the flags independent in the gate's
// eyes: verified wins, and the nudge merge never wipes a verification
t('verify after nudge',   aegis_mfa_mark_verified('root') === true);
t('re-nudge keeps verify', aegis_mfa_mark_nudged('root') === true
                           && aegis_mfa_session_verified() === true
                           && aegis_mfa_session_nudged() === true);

// switch drops the nudge with the rest of the namespace
$_SESSION['unraid_user'] = 'lazaros';
t('switch drops nudge',   aegis_mfa_session_nudged() === false);
t('nudge fresh user',     aegis_mfa_mark_nudged('lazaros') === true
                           && aegis_mfa_session_nudged() === true
                           && aegis_mfa_session_verified() === false);

// navigation detector: the nudge bounces page loads, never background
// traffic. Fetch Metadata decides when present, Accept when it is not,
// and anything ambiguous passes.
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

// user status / secrets
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
aegis_mfa_set_last_step('root', 120);
t('last step no regress',  aegis_mfa_get_last_step('root') === 150);
aegis_mfa_set_last_step('ghost', 99);
$ghost = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json')['users']['ghost'] ?? null;
t('last step ghost noop',  $ghost === null);

// lockout
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

// window reset: an old first_at starts a fresh window
$ip2 = '198.51.100.7';
aegis_mfa_record_failure($ip2, 'media', 1000);
aegis_mfa_record_failure($ip2, 'media', 1010);
t('window resets count',   aegis_mfa_record_failure($ip2, 'media', 1200) === 2);

// clear
aegis_mfa_clear_failures($ip);
t('cleared unlocks',       aegis_mfa_is_locked($ip, 1020) === false);

// prune: expired window entries vanish, active locks stay
aegis_mfa_record_failure('192.0.2.1', 'x', 1000);          // stale after window
aegis_mfa_record_failure('192.0.2.2', 'x', 5000);          // fresh
for ($i = 0; $i < 3; $i++) aegis_mfa_record_failure('192.0.2.3', 'x', 5000);  // locked
aegis_mfa_prune_lockouts(5050);
$d = aegis_mfa_read_json(aegis_mfa_lockout_path());
t('prune drops stale',     !isset($d['failures']['192.0.2.1']));
t('prune keeps fresh',     isset($d['failures']['192.0.2.2']));
t('prune keeps locked',    isset($d['failures']['192.0.2.3']));

// user enumeration / sync (injected getent fixtures)
// fixture mirroring a real Unraid box: root + two web users, plus system
// accounts and locked accounts that must be excluded.
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

// sync onto an empty secrets store: all live users become pending
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

// second run is idempotent: nothing added or removed
$r2 = aegis_mfa_sync_users($fixture, 2000);
t('sync idempotent',       $r2['added'] === [] && $r2['removed'] === []);

// an enrolled user is left untouched by sync
aegis_mfa_update_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', function ($s) {
    $s['users']['root'] = ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'];
    return $s;
});
aegis_mfa_sync_users($fixture, 3000);
t('sync keeps enrolled',   aegis_mfa_user_status('root', 3000) === 'enrolled');

// a user removed from the system is dropped from secrets
$smaller = function (string $db) use ($fixture): array {
    return array_values(array_filter($fixture($db), fn($l) => strpos($l, 'media:') !== 0));
};
$r3 = aegis_mfa_sync_users($smaller, 4000);
t('sync drops removed',    $r3['removed'] === ['media']);
t('removed user gone',     aegis_mfa_user_status('media', 4000) === 'none');
t('other users survive',   aegis_mfa_user_status('root', 4000) === 'enrolled');

// an empty account read never wipes enrolments: treated as a failed read,
// because root always exists on a box where webGUI login works at all
$empty = function (string $db): array { return []; };
$syncBefore = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
$rg = aegis_mfa_sync_users($empty, 5000);
t('sync empty read skipped',   ($rg['skipped'] ?? '') === 'no_live_users');
t('sync empty removed none',   $rg['removed'] === [] && $rg['added'] === []);
t('sync empty file untouched', aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === $syncBefore);
t('sync empty root survives',  aegis_mfa_user_status('root', 5000) === 'enrolled');

// an ENROLLED user missing from the live list must NOT be deleted: a
// background sync must never destroy real setup effort. This is the
// "Synced. removed: 1" that wiped an enrolled root on live hardware.
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root'  => ['status' => 'enrolled', 'secret' => 'S', 'backup_codes' => ['a'], 'backup_codes_used' => []],
    'ghost' => ['status' => 'pending', 'grace_until' => 9999999999],
]]);
$listNoRoot = function (string $db): array {
    // shadow + passwd for a single non-root user; root absent from both
    if ($db === 'shadow') return ['alice:$6$x'];
    if ($db === 'passwd') return ['alice:x:1000:1000::/home/alice:/bin/bash'];
    return [];
};
$rr = aegis_mfa_sync_users($listNoRoot, 6000);
t('no-root list skips removals', ($rr['skipped'] ?? '') === 'no_root_in_list');
t('no-root list keeps enrolled root', aegis_mfa_user_status('root', 6000) === 'enrolled');
t('no-root list keeps pending ghost too', isset(aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json')['users']['ghost']));
t('no-root list still adds alice', in_array('alice', $rr['added'], true));

// a trustworthy list (root present) prunes a stale PENDING user but still
// spares an enrolled one that is absent
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

// summary
echo "\nhelpers.test.php: {$pass} passed, {$fail} failed\n";
// cleanup
foreach (glob("$work/flash/*") as $g) @unlink($g);
foreach (glob("$work/state/*") as $g) @unlink($g);
foreach (glob("$work/conc/*") as $g) @unlink($g);
foreach (glob("$work/sess_*") as $g) @unlink($g);
@rmdir("$work/flash"); @rmdir("$work/state"); @rmdir("$work/conc"); @rmdir($work);
exit($fail === 0 ? 0 : 1);
