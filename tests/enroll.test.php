<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// enrolment state machine, csrf and bypass tokens. run: php tests/enroll.test.php

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

    $raw = aegis_totp_b32decode($b32secret);
    return aegis_totp_hotp($raw, intdiv(time(), 30) + $offset);
}

$tok = aegis_mfa_csrf_token();
t('csrf token length', strlen($tok) === 64);
t('csrf token stable', aegis_mfa_csrf_token() === $tok);
t('csrf check valid', aegis_mfa_csrf_check($tok) === true);
t('csrf check wrong', aegis_mfa_csrf_check('deadbeef') === false);
t('csrf check empty', aegis_mfa_csrf_check('') === false);

$enr = aegis_mfa_begin_enrollment('root', 'Aegis MFA', 'raptor1');
t('begin returns secret', isset($enr['secret']) && preg_match('/^[A-Z2-7]{32}$/', $enr['secret']));
t('begin returns uri',    str_starts_with($enr['uri'], 'otpauth://totp/Aegis%20MFA:root%40raptor1?'));
t('begin uri has secret', strpos($enr['uri'], 'secret=' . $enr['secret']) !== false);
t('begin 10 backup codes', count($enr['backup_codes']) === 10);
t('begin state held',      aegis_mfa_enroll_state()['user'] === 'root');
t('begin secret not on disk', aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === null);
t('begin flag unset',      aegis_mfa_enroll_state()['totp_ok'] === false);

$res = aegis_mfa_commit_enrollment($enr['backup_codes'][0]);
t('commit before verify refused',  ($res['ok'] ?? true) === false);
t('commit before verify reason',   ($res['reason'] ?? '') === 'totp_not_verified');
t('commit before verify no write', aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === null);
t('commit before verify keeps state', aegis_mfa_enroll_state() !== null);

$secret = $enr['secret'];
t('enroll verify correct', aegis_mfa_verify_enrollment_totp(code_for($secret)) === true);
t('enroll verify wrong',   aegis_mfa_verify_enrollment_totp('000000') === false);
t('enroll verify window',  aegis_mfa_verify_enrollment_totp(code_for($secret, -1)) === true);

$res = aegis_mfa_commit_enrollment('fffff-fffff');
t('commit bad backup fails', ($res['ok'] ?? true) === false);
t('commit bad reason',       ($res['reason'] ?? '') === 'bad_backup_confirm');
t('commit bad no write',     aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json') === null);
t('commit bad keeps state',  aegis_mfa_enroll_state() !== null);

$confirm = $enr['backup_codes'][2];
$res = aegis_mfa_commit_enrollment($confirm);
t('commit ok', ($res['ok'] ?? false) === true);
t('commit clears session', aegis_mfa_enroll_state() === null);

$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('committed status enrolled', $sec['users']['root']['status'] === 'enrolled');
t('committed secret matches',  $sec['users']['root']['secret'] === $secret);
t('committed 10 hashed codes', count($sec['users']['root']['backup_codes']) === 10);
t('committed confirm consumed', $sec['users']['root']['backup_codes_used'] === [2]);
t('committed codes hashed',     str_starts_with($sec['users']['root']['backup_codes'][0], '$2y$'));

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'enforce_after' => 0, 'lockout' => ['threshold' => 5, 'window_seconds' => 300, 'lock_seconds' => 600]]);
aegis_mfa_config(true);
$_SESSION['unraid_login'] = time();
$_SESSION['unraid_user']  = 'root';
$_SERVER['REMOTE_ADDR']   = '203.0.113.5';
unset($_SESSION['aegis_mfa']);
$v = aegis_mfa_verify_submission('root', code_for($secret));
t('enrolled secret verifies via gate', ($v['ok'] ?? false) === true);

unset($_SESSION['aegis_mfa']);
aegis_mfa_clear_failures('203.0.113.5');
$vb = aegis_mfa_verify_submission('root', $confirm);
t('consumed backup code rejected', ($vb['ok'] ?? true) === false);

unset($_SESSION['aegis_mfa']);
aegis_mfa_clear_failures('203.0.113.5');
$vb2 = aegis_mfa_verify_submission('root', $enr['backup_codes'][5]);
t('other backup code accepted', ($vb2['ok'] ?? false) === true);

aegis_mfa_begin_enrollment('lazaros');
t('cancel target present', aegis_mfa_enroll_state() !== null);
aegis_mfa_cancel_enrollment();
t('cancel clears state', aegis_mfa_enroll_state() === null);

aegis_mfa_begin_enrollment('lazaros');
aegis_mfa_verify_enrollment_totp(code_for(aegis_mfa_enroll_state()['secret']));
t('verify sets flag',    aegis_mfa_enroll_state()['totp_ok'] === true);
aegis_mfa_begin_enrollment('lazaros');
t('re-begin clears flag', aegis_mfa_enroll_state()['totp_ok'] === false);
aegis_mfa_cancel_enrollment();

$token = aegis_mfa_create_bypass_token('newuser', 3600);
t('bypass returns token', is_string($token) && strlen($token) === 48);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('bypass user created pending', $sec['users']['newuser']['status'] === 'pending');
t('bypass hash stored',          str_starts_with($sec['users']['newuser']['bypass_hash'], '$2y$'));

t('bypass wrong token',   aegis_mfa_consume_bypass_token('newuser', 'wrong') === false);
t('bypass unknown user',  aegis_mfa_consume_bypass_token('ghost', $token) === false);
t('bypass correct token', aegis_mfa_consume_bypass_token('newuser', $token) === true);

t('bypass single use',    aegis_mfa_consume_bypass_token('newuser', $token) === false);

$token2 = aegis_mfa_create_bypass_token('newuser', 3600);
t('expired bypass refused', aegis_mfa_consume_bypass_token('newuser', $token2, time() + 7200) === false);

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => false]);
aegis_mfa_config(true);
t('set enabled true',  aegis_mfa_set_enabled(true) && aegis_mfa_config(true)['enabled'] === true);
t('set enabled false', aegis_mfa_set_enabled(false) && aegis_mfa_config(true)['enabled'] === false);

t('enforce now', aegis_mfa_enforce_now(5000) && aegis_mfa_config(true)['enforce_after'] === 5000);
t('dry run sets future', aegis_mfa_start_dry_run(24, 1000) && aegis_mfa_config(true)['enforce_after'] === 1000 + 24 * 3600);
t('set grace days', aegis_mfa_set_grace_days(14) && aegis_mfa_config(true)['grace_period_days'] === 14);
t('grace floor at 0', aegis_mfa_set_grace_days(-5) && aegis_mfa_config(true)['grace_period_days'] === 0);

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

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root' => ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
               'backup_codes' => array_fill(0, 10, '$2y$dummy'), 'backup_codes_used' => [1, 2]],
]]);
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => true, 'grace_period_days' => 7]);
aegis_mfa_config(true);

t('reset to pending', aegis_mfa_reset_user('root', true, 1000) === true);
t('reset status pending', aegis_mfa_user_status('root', 1000) === 'pending');
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('reset grace set', $sec['users']['root']['grace_until'] === 1000 + 7 * 86400);
t('reset dropped secret', !isset($sec['users']['root']['secret']));

t('regen non-enrolled null', aegis_mfa_begin_backup_regen('root') === null);
t('regen no state yet', aegis_mfa_regen_state() === null);

// seen_at: set once, on the account's own first appearance in the webGUI
t('unseen by default',   aegis_mfa_seen_webgui('root') === false);
t('mark seen writes',    aegis_mfa_mark_seen('root', 4242) === true);
t('seen after mark',     aegis_mfa_seen_webgui('root') === true);
t('mark seen idempotent', aegis_mfa_mark_seen('root', 9999) === false);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('seen_at keeps first',  $sec['users']['root']['seen_at'] === 4242);
t('empty user not marked',   aegis_mfa_mark_seen('') === false);
t('junk name not marked',    aegis_mfa_mark_seen('../../etc/passwd') === false);
t('spaced name not marked',  aegis_mfa_mark_seen('root x') === false);

// the account can reach the webGUI before any sync has run: the record must be created,
// and a later sync must fill in the status without losing seen_at
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => []]);
t('marked before any sync', aegis_mfa_mark_seen('root', 700) === true);
t('seen without a record',  aegis_mfa_seen_webgui('root') === true);
t('status stays none',      aegis_mfa_user_status('root', 700) === 'none');
$before = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('no status invented',     !isset($before['users']['root']['status']));

$getentRoot = function (string $db): array {
    if ($db === 'passwd') return ['root:x:0:0::/root:/bin/bash'];
    if ($db === 'shadow') return ['root:$6$a$h:19000:0:99999:7:::'];
    return [];
};
$r = aegis_mfa_sync_users($getentRoot, 800);
t('sync adopts the record', in_array('root', $r['added'], true));
$after = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('sync fills the status',  $after['users']['root']['status'] === 'pending');
t('sync keeps seen_at',     $after['users']['root']['seen_at'] === 700);

aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root' => ['status' => 'enrolled', 'secret' => 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
               'backup_codes' => array_fill(0, 10, '$2y$dummy'), 'backup_codes_used' => [0, 1, 2, 3]],
]]);
$new = aegis_mfa_begin_backup_regen('root');
t('regen returns 10 plain', is_array($new) && count($new) === 10);
t('regen format', (bool)preg_match('/^[0-9a-f]{5}-[0-9a-f]{5}$/', $new[0]));
t('regen state held', (aegis_mfa_regen_state()['user'] ?? '') === 'root');

// a pending re-issue is one account's business, whoever unraid lets log in later
$_SESSION['unraid_user'] = 'someone-else';
t('regen hidden from another account', aegis_mfa_regen_state() === null);
t('commit refused for another account',
    (aegis_mfa_commit_backup_regen($new[0])['reason'] ?? '') === 'no_regen');
$_SESSION['unraid_user'] = 'root';
t('regen back for its owner', (aegis_mfa_regen_state()['user'] ?? '') === 'root');

// nothing is written until a code is typed back
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('regen defers the write', $sec['users']['root']['backup_codes'][0] === '$2y$dummy');
t('regen keeps old used',   $sec['users']['root']['backup_codes_used'] === [0, 1, 2, 3]);

t('regen bad confirm', (aegis_mfa_commit_backup_regen('00000-00000')['reason'] ?? '') === 'bad_confirm');
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('bad confirm writes nothing', $sec['users']['root']['backup_codes'][0] === '$2y$dummy');
t('bad confirm keeps state', aegis_mfa_regen_state() !== null);

t('regen commit ok', (aegis_mfa_commit_backup_regen($new[4])['ok'] ?? false) === true);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('commit swaps the hashes', $sec['users']['root']['backup_codes'][0] !== '$2y$dummy');
t('commit spends the typed one', $sec['users']['root']['backup_codes_used'] === [4]);
t('commit remaining 9', aegis_mfa_backup_codes_remaining('root') === 9);
t('commit clears state', aegis_mfa_regen_state() === null);
t('commit twice refused', (aegis_mfa_commit_backup_regen($new[4])['reason'] ?? '') === 'no_regen');

// the typed code really is spent, and a sibling really works
t('spent code refused', aegis_mfa_consume_backup_code('root', $new[4]) === false);
t('fresh code accepted', aegis_mfa_consume_backup_code('root', $new[7]) === true);

aegis_mfa_begin_backup_regen('root');
aegis_mfa_cancel_backup_regen();
t('cancel drops state', aegis_mfa_regen_state() === null);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('cancel keeps old codes', count($sec['users']['root']['backup_codes']) === 10);

// the php session outlives an uninstall, so a pending re-issue must not survive its enrolment
$keepSec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => []]);
t('regen dropped when not enrolled', aegis_mfa_regen_state() === null);
t('regen state really cleared',      !isset($_SESSION['aegis_mfa_regen']));
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', $keepSec);

$fresh = aegis_mfa_begin_backup_regen('root');
t('regen restarts fine', is_array($fresh) && count($fresh) === 10);
t('regen expires after 30 min',
    aegis_mfa_regen_state(time() + 1801) === null);

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
// root and lazaros have reached the webGUI, media is a share account that never has
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root'    => ['status' => 'enrolled', 'secret' => 'X', 'enrolled_at' => 900, 'seen_at' => 800,
                  'backup_codes' => array_fill(0, 10, 'h'), 'backup_codes_used' => [0]],
    'lazaros' => ['status' => 'pending', 'grace_until' => 5000, 'seen_at' => 850],
    'media'   => ['status' => 'pending', 'grace_until' => 100],
]]);
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json',
    ['enabled' => true, 'enforce_after' => 0, 'grace_period_days' => 7, 'trust_lan' => ['10.0.0.0/24']]);
aegis_mfa_config(true);

aegis_mfa_write_json(aegis_mfa_lockout_path(), ['failures' => [
    '1.1.1.1' => ['count' => 3, 'last_at' => 2000, 'locked_until' => 9999999999],
    '2.2.2.2' => ['count' => 2, 'last_at' => 2000, 'locked_until' => 0],
]]);

$sum = aegis_mfa_admin_summary($fixture, 2000);
t('summary enabled',        $sum['enabled'] === true);
t('summary enforcing',      $sum['enforcing'] === true);
t('summary not dry-run',    $sum['dry_run'] === false);
t('summary enrolled count', $sum['enrolled'] === 1);
t('summary pending count',  $sum['pending'] === 1);
t('summary total counts seen only', $sum['total_users'] === 2);
t('summary lists everyone',         $sum['listed_users'] === 3);
$byName = [];
foreach ($sum['users'] as $su) $byName[$su['name']] = $su;
t('summary marks root seen',    $byName['root']['seen'] === true);
t('summary marks media unseen', $byName['media']['seen'] === false);

// enrolled counts as seen without a seen_at, or every upgrade and every CLI report reads 0
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'root'  => ['status' => 'enrolled', 'secret' => 'X', 'enrolled_at' => 900],
    'media' => ['status' => 'pending', 'grace_until' => 100],
]]);
$s2 = aegis_mfa_admin_summary($fixture, 3000);
t('enrolled seen without seen_at', $s2['enrolled'] === 1 && $s2['total_users'] === 1);
t('helper agrees',                 aegis_mfa_seen_webgui('root') === true);
t('pending without seen_at unseen', aegis_mfa_seen_webgui('media') === false);
t('unseen still carries status', $byName['media']['status'] === 'locked');
t('summary locked ips',     $sum['locked_ips'] === 1);
t('summary failures today', $sum['failures_today'] === 5);
t('summary trust lan',      $sum['trust_lan'] === ['10.0.0.0/24']);
t('summary grace days',     $sum['grace_days'] === 7);

$byName = [];
foreach ($sum['users'] as $u) $byName[$u['name']] = $u;
t('summary root enrolled',  $byName['root']['status'] === 'enrolled');
t('summary root backups',   $byName['root']['backup_remaining'] === 9);
t('summary media locked',   $byName['media']['status'] === 'locked');
t('summary lazaros pending', $byName['lazaros']['status'] === 'pending');

aegis_mfa_start_dry_run(24, 2000);
$sum = aegis_mfa_admin_summary($fixture, 2000);
t('summary dry-run true', $sum['dry_run'] === true);
t('summary enforcing false in dry-run', $sum['enforcing'] === false);

// passkey enrolment path: begin_enrollment(method='passkey') plus a stubbed passkey_cred - a real ceremony needs a browser, that crypto is covered in webauthn.test.php
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => []]);
$pkEnr = aegis_mfa_begin_enrollment('pkuser', 'Aegis MFA', 'raptor1', 'passkey');
t('passkey begin method',        $pkEnr['method'] === 'passkey');
t('passkey begin no secret',     !isset($pkEnr['secret']));
t('passkey begin 10 backup codes', count($pkEnr['backup_codes']) === 10);
t('passkey begin state method',  aegis_mfa_enroll_state()['method'] === 'passkey');
t('passkey begin ok flag unset', aegis_mfa_enroll_state()['passkey_ok'] === false);

$res = aegis_mfa_commit_enrollment($pkEnr['backup_codes'][0]);
t('passkey commit before verify refused', ($res['ok'] ?? true) === false);
t('passkey commit before verify reason',  ($res['reason'] ?? '') === 'passkey_not_verified');

// simulate a completed ceremony the way aegis_mfa_verify_enrollment_passkey() would leave it
$_SESSION['aegis_mfa_enroll']['passkey_ok']   = true;
$_SESSION['aegis_mfa_enroll']['passkey_cred'] = [
    'id' => 'test-cred-id', 'public_key' => ['kty' => 2, 'crv' => 1, 'x' => 'eA==', 'y' => 'eQ=='],
    'sign_count' => 0, 'created_at' => time(), 'last_used_at' => null, 'label' => 'Passkey',
];
$confirm = $pkEnr['backup_codes'][3];
$res = aegis_mfa_commit_enrollment($confirm);
t('passkey commit ok',           ($res['ok'] ?? false) === true);
t('passkey commit clears session', aegis_mfa_enroll_state() === null);

$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('passkey user enrolled',          $sec['users']['pkuser']['status'] === 'enrolled');
t('passkey user no totp secret',    !isset($sec['users']['pkuser']['secret']));
t('passkey user has one passkey',   count($sec['users']['pkuser']['passkeys']) === 1);
t('passkey user passkey id',        $sec['users']['pkuser']['passkeys'][0]['id'] === 'test-cred-id');
t('passkey user backup codes stored', count($sec['users']['pkuser']['backup_codes']) === 10);
t('passkey user confirm consumed',  $sec['users']['pkuser']['backup_codes_used'] === [3]);

// aegis_mfa_setup_access_ok(): the one shared authorization rule for every pre-2FA surface
$_SESSION['unraid_user'] = 'pkuser';
unset($_SESSION['aegis_mfa'], $_SESSION['aegis_mfa_token_ok']);
t('access ok for a user with no record yet', aegis_mfa_setup_access_ok('freshuser') === true); // status 'none'
t('access denied for enrolled, unverified, no token', aegis_mfa_setup_access_ok('pkuser') === false);
aegis_mfa_mark_verified('pkuser');
t('access ok once session verified', aegis_mfa_setup_access_ok('pkuser') === true);
unset($_SESSION['aegis_mfa']);
$_SESSION['aegis_mfa_token_ok'] = ['user' => 'pkuser', 'until' => time() + 3600];
t('access ok with a valid bypass token', aegis_mfa_setup_access_ok('pkuser') === true);
$_SESSION['aegis_mfa_token_ok'] = ['user' => 'pkuser', 'until' => time() - 1];
t('access denied with an expired bypass token', aegis_mfa_setup_access_ok('pkuser') === false);
unset($_SESSION['aegis_mfa_token_ok']);
t('access denied for an empty user', aegis_mfa_setup_access_ok('') === false);

// passkey management (AegisMfaAdmin.php): add/remove/rename and the last-factor guard
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', ['version' => 1, 'users' => [
    'onlypasskey' => [
        'status' => 'enrolled', 'backup_codes' => array_fill(0, 10, 'h'), 'backup_codes_used' => [0],
        'passkeys' => [['id' => 'pk-a', 'public_key' => [], 'sign_count' => 0, 'label' => 'Only one']],
    ],
    'both' => [
        'status' => 'enrolled', 'secret' => 'X', 'backup_codes' => array_fill(0, 10, 'h'), 'backup_codes_used' => [0],
        'passkeys' => [['id' => 'pk-b', 'public_key' => [], 'sign_count' => 0, 'label' => 'Backup factor']],
    ],
]]);

$r = aegis_mfa_remove_passkey('onlypasskey', 'pk-a');
t('remove last factor refused', ($r['ok'] ?? true) === false);
t('remove last factor reason',  ($r['reason'] ?? '') === 'last_factor');
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('remove last factor kept the passkey', count($sec['users']['onlypasskey']['passkeys']) === 1);

$r = aegis_mfa_remove_passkey('both', 'pk-b');
t('remove passkey with a totp backup ok', ($r['ok'] ?? false) === true);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('remove passkey with a totp backup removed', count($sec['users']['both']['passkeys']) === 0);

$r = aegis_mfa_remove_passkey('both', 'no-such-id');
t('remove unknown passkey id refused', ($r['ok'] ?? true) === false);
t('remove unknown passkey reason',     ($r['reason'] ?? '') === 'not_found');

t('rename passkey', aegis_mfa_rename_passkey('onlypasskey', 'pk-a', 'My phone') === true);
$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('rename passkey persisted',   $sec['users']['onlypasskey']['passkeys'][0]['label'] === 'My phone');
t('rename unknown passkey no-op', aegis_mfa_rename_passkey('onlypasskey', 'nope', 'X') === false);

// adding TOTP to an already-enrolled, passkey-only account (AegisMfaAdmin.php), additive like aegis_mfa_add_passkey
$_SESSION['unraid_user'] = 'onlypasskey';
t('begin totp add for an unenrolled account', aegis_mfa_begin_totp_add('nosuchuser') === null);

$add = aegis_mfa_begin_totp_add('onlypasskey');
t('begin totp add returns a secret', is_array($add) && !empty($add['secret']));
t('begin totp add returns a uri',    is_array($add) && strpos($add['uri'], 'otpauth://') === 0);

$state = aegis_mfa_totp_add_state();
t('totp add state visible to the same session', $state !== null && $state['user'] === 'onlypasskey');
// AegisMfa.page rebuilds the QR from $state['secret'] + $state['user'] at render time, same pattern
// as the original wizard's setup.php - no derived uri is ever stored, only the secret it comes from,
// so there's nothing that can go stale or desync between what begin() returned and what gets rendered
t('totp add state has no stored uri, only the secret it derives from', !array_key_exists('uri', $state));
t('totp add state can rebuild the same uri begin() returned', is_array($state)
    && aegis_totp_uri($state['secret'], $state['user'] . '@' . aegis_mfa_server_name(), 'Aegis MFA') === $add['uri']);

$_SESSION['unraid_user'] = 'both';
t('totp add state hidden from a different session', aegis_mfa_totp_add_state() === null);
$_SESSION['unraid_user'] = 'onlypasskey';

$r = aegis_mfa_commit_totp_add('000000');
t('commit totp add rejects a wrong code', ($r['ok'] ?? true) === false);
t('commit totp add wrong code reason',    ($r['reason'] ?? '') === 'bad_code');

$r = aegis_mfa_commit_totp_add(code_for($add['secret']));
t('commit totp add accepts the right code', ($r['ok'] ?? false) === true);

$sec = aegis_mfa_read_json(AEGIS_MFA_FLASH_DIR . '/secrets.json');
t('totp add wrote the secret',           $sec['users']['onlypasskey']['secret'] === $add['secret']);
t('totp add kept the existing passkey',  count($sec['users']['onlypasskey']['passkeys']) === 1);
t('totp add did not touch backup codes', $sec['users']['onlypasskey']['backup_codes_used'] === [0]);
t('totp add state cleared after commit', aegis_mfa_totp_add_state() === null);

aegis_mfa_begin_totp_add('onlypasskey');
aegis_mfa_cancel_totp_add();
t('cancel totp add clears session state', aegis_mfa_totp_add_state() === null);

// webauthn_assume_https: a TLS-terminating proxy leaves $_SERVER['HTTPS'] unset on a real https:// request
// UI-gate override only, not a security check - verification always checks the origin the browser itself reports
aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['webauthn_rp_origin' => 'https://tower.example.com']);
aegis_mfa_config(true);
$_SERVER['HTTP_HOST'] = 'tower.example.com';
unset($_SERVER['HTTPS']);
t('proxy: plain http seen without the flag', aegis_mfa_webauthn_current_origin() === 'http://tower.example.com');
t('proxy: not available without the flag',   aegis_mfa_webauthn_available() === false);

t('proxy: set assume_https', aegis_mfa_set_webauthn_assume_https(true) === true);
t('proxy: origin now https with the flag', aegis_mfa_webauthn_current_origin() === 'https://tower.example.com');
t('proxy: available with the flag',        aegis_mfa_webauthn_available() === true);

t('proxy: unset assume_https', aegis_mfa_set_webauthn_assume_https(false) === true);
t('proxy: back to http once cleared', aegis_mfa_webauthn_current_origin() === 'http://tower.example.com');

// a real HTTPS connection still works regardless of the flag either way
$_SERVER['HTTPS'] = 'on';
t('real https unaffected by the flag', aegis_mfa_webauthn_current_origin() === 'https://tower.example.com');
unset($_SERVER['HTTPS'], $_SERVER['HTTP_HOST']);

echo "\nenroll.test.php: {$pass} passed, {$fail} failed\n";
foreach (glob("$work/flash/*") as $g) @unlink($g);
foreach (glob("$work/state/*") as $g) @unlink($g);
foreach (glob("$work/sess_*") as $g) @unlink($g);
@rmdir("$work/flash"); @rmdir("$work/state"); @rmdir($work);
exit($fail === 0 ? 0 : 1);
