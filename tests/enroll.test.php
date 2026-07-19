<?php
/*
 * Aegis MFA - enrolment + admin test suite
 * run: php tests/enroll.test.php
 * exit 0 on full pass, 1 on any failure
 */

$work = sys_get_temp_dir() . '/aegis-mfa-enroll-' . getmypid();
@mkdir($work . '/flash', 0700, true);
define('AEGIS_MFA_FLASH_DIR', $work . '/flash');
define('AEGIS_MFA_STATE_DIR', $work . '/state');
ini_set('session.save_path', $work);

require __DIR__ . '/../source/include/AegisMfaEnroll.php';
require __DIR__ . '/../source/include/AegisMfaAdmin.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

aegis_mfa_session_ensure();
$REF_RAW = '12345678901234567890';
function code_for(string $b32secret, int $offset = 0): string {
    // compute the current code for a given base32 secret
    $raw = aegis_totp_b32decode($b32secret);
    return aegis_totp_hotp($raw, intdiv(time(), 30) + $offset);
}

// CSRF
$tok = aegis_mfa_csrf_token();
t('csrf token length', strlen($tok) === 64);
t('csrf token stable', aegis_mfa_csrf_token() === $tok);
t('csrf check valid', aegis_mfa_csrf_check($tok) === true);
t('csrf check wrong', aegis_mfa_csrf_check('deadbeef') === false);
t('csrf check empty', aegis_mfa_csrf_check('') === false);

// ENROLMENT WIZARD
$enr = aegis_mfa_begin_enrollment('root', 'Aegis MFA', 'raptor1');
t('begin returns secret', isset($enr['secret']) && preg_match('/^[A-Z2-7]{32}$/', $enr['secret']));
t('begin returns uri',    str_starts_with($enr['uri'], 'otpauth://totp/Aegis%20MFA:root%40raptor1?'));
t('begin uri has secret', strpos($enr['uri'], 'secret=' . $enr['secret']) !== false);
t('begin 10 backup codes', count($enr['backup_codes']) === 10);
t('begin state held',      aegis_mfa_enroll_state()['user'] === 'root');
t('begin secret not on disk', aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === null);
t('begin flag unset',      aegis_mfa_enroll_state()['totp_ok'] === false);

// commit before step 2 has verified -> refused, the order is server-side
$res = aegis_mfa_commit_enrollment($enr['backup_codes'][0]);
t('commit before verify refused',  ($res['ok'] ?? true) === false);
t('commit before verify reason',   ($res['reason'] ?? '') === 'totp_not_verified');
t('commit before verify no write', aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === null);
t('commit before verify keeps state', aegis_mfa_enroll_state() !== null);

// step 2: verify a TOTP against the pending secret
$secret = $enr['secret'];
t('enroll verify correct', aegis_mfa_verify_enrollment_totp(code_for($secret)) === true);
t('enroll verify wrong',   aegis_mfa_verify_enrollment_totp('000000') === false);
t('enroll verify window',  aegis_mfa_verify_enrollment_totp(code_for($secret, -1)) === true);

// step 3: commit with a WRONG backup confirm -> refused, nothing written
$res = aegis_mfa_commit_enrollment('fffff-fffff');
t('commit bad backup fails', ($res['ok'] ?? true) === false);
t('commit bad reason',       ($res['reason'] ?? '') === 'bad_backup_confirm');
t('commit bad no write',     aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === null);
t('commit bad keeps state',  aegis_mfa_enroll_state() !== null);

// step 3: commit with a CORRECT backup confirm -> enrolled
$confirm = $enr['backup_codes'][2];   // use the 3rd code as the confirm
$res = aegis_mfa_commit_enrollment($confirm);
t('commit ok', ($res['ok'] ?? false) === true);
t('commit clears session', aegis_mfa_enroll_state() === null);

$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('committed status enrolled', $sec['users']['root']['status'] === 'enrolled');
t('committed secret matches',  $sec['users']['root']['secret'] === $secret);
t('committed 10 hashed codes', count($sec['users']['root']['backup_codes']) === 10);
t('committed confirm consumed', $sec['users']['root']['backup_codes_used'] === [2]);
t('committed codes hashed',     str_starts_with($sec['users']['root']['backup_codes'][0], '$2y$'));

// the enrolled secret actually verifies through the real gate verifier
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'enforce_after' => 0, 'lockout' => ['threshold' => 5, 'window_seconds' => 300, 'lock_seconds' => 600]]);
aegis_mfa_config(true);
$_SESSION['unraid_login'] = time();
$_SESSION['unraid_user']  = 'root';
$_SERVER['REMOTE_ADDR']   = '203.0.113.5';
unset($_SESSION['aegis_mfa']);
$v = aegis_mfa_verify_submission('root', code_for($secret));
t('enrolled secret verifies via gate', ($v['ok'] ?? false) === true);

// the confirmed backup code (index 2) can no longer be used
unset($_SESSION['aegis_mfa']);
aegis_mfa_clear_failures('203.0.113.5');
$vb = aegis_mfa_verify_submission('root', $confirm);
t('consumed backup code rejected', ($vb['ok'] ?? true) === false);
// but another backup code still works
unset($_SESSION['aegis_mfa']);
aegis_mfa_clear_failures('203.0.113.5');
$vb2 = aegis_mfa_verify_submission('root', $enr['backup_codes'][5]);
t('other backup code accepted', ($vb2['ok'] ?? false) === true);

// cancel wipes an in-progress enrolment
aegis_mfa_begin_enrollment('lazaros');
t('cancel target present', aegis_mfa_enroll_state() !== null);
aegis_mfa_cancel_enrollment();
t('cancel clears state', aegis_mfa_enroll_state() === null);

// a restart resets the step-2 flag: the fresh secret must verify anew
aegis_mfa_begin_enrollment('lazaros');
aegis_mfa_verify_enrollment_totp(code_for(aegis_mfa_enroll_state()['secret']));
t('verify sets flag',    aegis_mfa_enroll_state()['totp_ok'] === true);
aegis_mfa_begin_enrollment('lazaros');
t('re-begin clears flag', aegis_mfa_enroll_state()['totp_ok'] === false);
aegis_mfa_cancel_enrollment();

// BYPASS TOKENS
$token = aegis_mfa_create_bypass_token('newuser', 3600);
t('bypass returns token', is_string($token) && strlen($token) === 48);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('bypass user created pending', $sec['users']['newuser']['status'] === 'pending');
t('bypass hash stored',          str_starts_with($sec['users']['newuser']['bypass_hash'], '$2y$'));

t('bypass wrong token',   aegis_mfa_consume_bypass_token('newuser', 'wrong') === false);
t('bypass unknown user',  aegis_mfa_consume_bypass_token('ghost', $token) === false);
t('bypass correct token', aegis_mfa_consume_bypass_token('newuser', $token) === true);
// single use: second attempt fails
t('bypass single use',    aegis_mfa_consume_bypass_token('newuser', $token) === false);

// expired token is refused
$token2 = aegis_mfa_create_bypass_token('newuser', 3600);
t('expired bypass refused', aegis_mfa_consume_bypass_token('newuser', $token2, time() + 7200) === false);

// ADMIN: config writers
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => false]);
aegis_mfa_config(true);
t('set enabled true',  aegis_mfa_set_enabled(true) && aegis_mfa_config(true)['enabled'] === true);
t('set enabled false', aegis_mfa_set_enabled(false) && aegis_mfa_config(true)['enabled'] === false);

t('enforce now', aegis_mfa_enforce_now(5000) && aegis_mfa_config(true)['enforce_after'] === 5000);
t('dry run sets future', aegis_mfa_start_dry_run(24, 1000) && aegis_mfa_config(true)['enforce_after'] === 1000 + 24 * 3600);
t('set grace days', aegis_mfa_set_grace_days(14) && aegis_mfa_config(true)['grace_period_days'] === 14);
t('grace floor at 0', aegis_mfa_set_grace_days(-5) && aegis_mfa_config(true)['grace_period_days'] === 0);

// ADMIN: CIDR validation + trust lan
t('valid v4 cidr',   aegis_mfa_valid_cidr('10.0.0.0/24') === true);
t('valid v4 bare',   aegis_mfa_valid_cidr('10.0.0.4') === true);
t('valid v6 cidr',   aegis_mfa_valid_cidr('fd00::/64') === true);
t('valid v6 bare',   aegis_mfa_valid_cidr('::1') === true);
t('invalid junk',    aegis_mfa_valid_cidr('banana') === false);
t('invalid bits',    aegis_mfa_valid_cidr('10.0.0.0/xx') === false);
t('invalid v4 /33',  aegis_mfa_valid_cidr('10.0.0.0/33') === false);
t('invalid empty',   aegis_mfa_valid_cidr('') === false);

$r = aegis_mfa_set_trust_lan(['10.0.0.0/24', 'banana', '192.168.1.0/24', '10.0.0.0/24', '  ']);
t('trust lan accepts good', $r['accepted'] === ['10.0.0.0/24', '192.168.1.0/24']);
t('trust lan rejects bad',  $r['rejected'] === ['banana']);
t('trust lan dedups',       count($r['accepted']) === 2);
t('trust lan persisted',    aegis_mfa_config(true)['trust_lan'] === ['10.0.0.0/24', '192.168.1.0/24']);

$rp = aegis_mfa_set_trusted_proxies(['203.0.113.7', 'nope', '::1']);
t('proxies accept good', $rp['accepted'] === ['203.0.113.7', '::1']);
t('proxies reject bad',  $rp['rejected'] === ['nope']);

// ADMIN: per-user actions
// build an enrolled user to act on
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root' => ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
               'backup_codes' => array_fill(0, 10, '$2y$dummy'), 'backup_codes_used' => [1, 2]],
]]);
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => true, 'grace_period_days' => 7]);
aegis_mfa_config(true);

// reset with re-enroll -> back to pending with grace
t('reset to pending', aegis_mfa_reset_user('root', true, 1000) === true);
t('reset status pending', aegis_mfa_user_status('root', 1000) === 'pending');
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('reset grace set', $sec['users']['root']['grace_until'] === 1000 + 7 * 86400);
t('reset dropped secret', !isset($sec['users']['root']['secret']));

// regenerate on a non-enrolled user -> null
t('regen non-enrolled null', aegis_mfa_regenerate_backup_codes('root') === null);

// re-enroll then regenerate
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root' => ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
               'backup_codes' => array_fill(0, 10, '$2y$dummy'), 'backup_codes_used' => [0, 1, 2, 3]],
]]);
$new = aegis_mfa_regenerate_backup_codes('root');
t('regen returns 10 plain', is_array($new) && count($new) === 10);
t('regen format', (bool)preg_match('/^[0-9a-f]{5}-[0-9a-f]{5}$/', $new[0]));
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('regen resets used', $sec['users']['root']['backup_codes_used'] === []);
t('regen remaining 10', aegis_mfa_backup_codes_remaining('root') === 10);
// the new plain codes actually verify
t('regen codes hashed fresh', $sec['users']['root']['backup_codes'][0] !== '$2y$dummy');

// ADMIN: summary aggregation (injected user list)
$fixture = function (string $db): array {
    if ($db === 'passwd') return [
        'root:x:0:0::/root:/bin/bash',
        'lazaros:x:1000:100::/home/lazaros:/bin/bash',
        'media:x:1001:100::/home/media:/bin/false',
    ];
    if ($db === 'shadow') return [
        'root:$6$a$h:19000:0:99999:7:::',
        'lazaros:$6$b$h:19000:0:99999:7:::',
        'media:$6$c$h:19000:0:99999:7:::',
    ];
    return [];
};
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root'    => ['status' => 'enrolled', 'secret' => 'X', 'enrolled_at' => 900,
                  'backup_codes' => array_fill(0, 10, 'h'), 'backup_codes_used' => [0]],
    'lazaros' => ['status' => 'pending', 'grace_until' => 5000],
    'media'   => ['status' => 'pending', 'grace_until' => 100],   // expired -> locked
]]);
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'enforce_after' => 0, 'grace_period_days' => 7, 'trust_lan' => ['10.0.0.0/24']]);
aegis_mfa_config(true);
// seed some lockout state
aegis_mfa_write_json(aegis_mfa_lockout_path(), ['failures' => [
    '1.1.1.1' => ['count' => 3, 'last_at' => 2000, 'locked_until' => 9999999999],
    '2.2.2.2' => ['count' => 2, 'last_at' => 2000, 'locked_until' => 0],
]]);

$sum = aegis_mfa_admin_summary($fixture, 2000);
t('summary enabled',        $sum['enabled'] === true);
t('summary enforcing',      $sum['enforcing'] === true);
t('summary not dry-run',    $sum['dry_run'] === false);
t('summary enrolled count', $sum['enrolled'] === 1);
t('summary pending count',  $sum['pending'] === 2);   // pending + locked
t('summary total users',    $sum['total_users'] === 3);
t('summary locked ips',     $sum['locked_ips'] === 1);
t('summary failures today', $sum['failures_today'] === 5);
t('summary trust lan',      $sum['trust_lan'] === ['10.0.0.0/24']);
t('summary grace days',     $sum['grace_days'] === 7);

// per-user rows
$byName = [];
foreach ($sum['users'] as $u) $byName[$u['name']] = $u;
t('summary root enrolled',  $byName['root']['status'] === 'enrolled');
t('summary root backups',   $byName['root']['backup_remaining'] === 9);
t('summary media locked',   $byName['media']['status'] === 'locked');
t('summary lazaros pending', $byName['lazaros']['status'] === 'pending');

// dry-run reflected in summary
aegis_mfa_start_dry_run(24, 2000);
$sum = aegis_mfa_admin_summary($fixture, 2000);
t('summary dry-run true', $sum['dry_run'] === true);
t('summary enforcing false in dry-run', $sum['enforcing'] === false);

echo "\nenroll.test.php: {$pass} passed, {$fail} failed\n";
foreach (glob("$work/flash/*") as $g) @unlink($g);
foreach (glob("$work/state/*") as $g) @unlink($g);
foreach (glob("$work/sess_*") as $g) @unlink($g);
@rmdir("$work/flash"); @rmdir("$work/state"); @rmdir($work);
exit($fail === 0 ? 0 : 1);
