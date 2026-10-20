<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// the gate and the challenge verifier. run: php tests/gate.test.php

$work = sys_get_temp_dir() . '/aegis-mfa-gate-' . getmypid();
@mkdir($work, 0700, true);
define('AEGIS_MFA_FLASH_DIR', $work . '/flash');
define('AEGIS_MFA_STATE_DIR', $work . '/state');
ini_set('session.save_path', $work);

require __DIR__ . '/../source/include/AegisMfaGate.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

function set_config(array $cfg): void {
    aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', $cfg);
    aegis_mfa_config(true);
}
function set_secrets(array $sec): void {
    aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/secrets.json', $sec);
}
function login_as(string $user): void {
    $_SESSION['unraid_login'] = time();
    $_SESSION['unraid_user']  = $user;
    unset($_SESSION['aegis_mfa']);

    $_SERVER['REQUEST_METHOD']       = 'GET';
    $_SERVER['HTTP_SEC_FETCH_DEST']  = 'document';
    unset($_SERVER['HTTP_ACCEPT'], $_POST);
    $_POST = [];
}
function logout(): void { $_SESSION = []; }

$REF_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
$REF_RAW    = '12345678901234567890';
function ref_code(int $offset = 0): string {
    global $REF_RAW;
    return aegis_totp_hotp($REF_RAW, intdiv(time(), 30) + $offset);
}

aegis_mfa_session_ensure();
$_SERVER['REMOTE_ADDR'] = '203.0.113.50';

set_config(['enabled' => false]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
t('disabled -> allow', aegis_mfa_passed() === true);

set_config(['enabled' => true, 'enforce_after' => 0]);
touch(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');
t('rescue flag -> allow', aegis_mfa_passed() === true);
unlink(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');

set_config(['enabled' => true, 'enforce_after' => 0]);
logout();
t('no session -> allow', aegis_mfa_passed() === true);

set_secrets(['users' => []]);
login_as('root');
t('status none -> allow', aegis_mfa_passed() === true);

set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
t('pending unnudged -> challenge', aegis_mfa_passed() === false);
aegis_mfa_mark_nudged('root');
t('pending nudged -> allow', aegis_mfa_passed() === true);

$_SESSION['unraid_user'] = 'lazaros';
set_secrets(['users' => [
    'root'    => ['status' => 'pending', 'grace_until' => time() + 3600],
    'lazaros' => ['status' => 'pending', 'grace_until' => time() + 3600],
]]);
t('pending nudge other user -> challenge', aegis_mfa_passed() === false);

set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';
t('pending unnudged, xhr -> allow', aegis_mfa_passed() === true);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'style';
t('pending unnudged, asset -> allow', aegis_mfa_passed() === true);
$_SERVER['REQUEST_METHOD'] = 'POST';
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
t('pending unnudged, plain post -> allow', aegis_mfa_passed() === true);
$_POST['aegis_mfa_code'] = '123456';
t('pending unnudged, code post -> challenge', aegis_mfa_passed() === false);
$_POST = [];

login_as('root');
unset($_SERVER['HTTP_SEC_FETCH_DEST']);
$_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml';
t('pending unnudged, legacy html get -> challenge', aegis_mfa_passed() === false);
$_SERVER['HTTP_ACCEPT'] = 'application/json';
t('pending unnudged, legacy json get -> allow', aegis_mfa_passed() === true);
login_as('root');

set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
t('enrolled unverified -> challenge', aegis_mfa_passed() === false);

$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';
t('enrolled unverified, xhr -> challenge', aegis_mfa_passed() === false);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';

set_config(['enabled' => true, 'enforce_after' => 0, 'trust_lan' => ['203.0.113.0/24']]);
login_as('root');
t('enrolled + LAN -> allow', aegis_mfa_passed() === true);
set_config(['enabled' => true, 'enforce_after' => 0]);

login_as('root');
aegis_mfa_mark_verified('root');
t('enrolled + verified -> allow', aegis_mfa_passed() === true);

$_SESSION['unraid_user'] = 'lazaros';
set_secrets(['users' => [
    'root'    => ['status' => 'enrolled', 'secret' => $REF_SECRET],
    'lazaros' => ['status' => 'enrolled', 'secret' => $REF_SECRET],
]]);
t('verified other user -> challenge', aegis_mfa_passed() === false);

set_config(['enabled' => true, 'enforce_after' => time() + 3600]);
login_as('root');
t('dry-run unnudged -> challenge', aegis_mfa_passed() === false);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';
t('dry-run unnudged, xhr -> allow', aegis_mfa_passed() === true);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
aegis_mfa_mark_nudged('root');
t('dry-run nudged -> allow', aegis_mfa_passed() === true);

set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() - 10]]]);
login_as('root');
t('dry-run locked unnudged -> challenge', aegis_mfa_passed() === false);
aegis_mfa_mark_nudged('root');
t('dry-run locked nudged -> allow', aegis_mfa_passed() === true);

set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() - 10]]]);
login_as('root');
t('grace expired -> challenge', aegis_mfa_passed() === false);
aegis_mfa_mark_nudged('root');
t('grace expired + nudge -> still challenge', aegis_mfa_passed() === false);
login_as('root');

$SETUP = '/plugins/aegis.mfa/include/setup.php';

login_as('root');
$_SERVER['REQUEST_URI'] = '/Dashboard';
t('locked, other url -> challenge', aegis_mfa_passed() === false);
$_SERVER['REQUEST_URI'] = $SETUP;
t('locked, setup url -> allow', aegis_mfa_passed() === true);
$_SERVER['REQUEST_URI'] = $SETUP . '?user=root&token=abc';
t('locked, setup url + query -> allow', aegis_mfa_passed() === true);

set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
$_SERVER['REQUEST_URI'] = '/Main';
t('enrolled unverified, other url -> challenge', aegis_mfa_passed() === false);
$_SERVER['REQUEST_URI'] = $SETUP;
t('enrolled unverified, setup url -> allow', aegis_mfa_passed() === true);

// the passkey ceremony endpoints need the same exemption, or nginx's auth_request layer intercepts the JSON request and hands back an empty 401
$WEBAUTHN_PATHS = [
    '/plugins/aegis.mfa/include/webauthn.enroll.begin.php',
    '/plugins/aegis.mfa/include/webauthn.enroll.finish.php',
    '/plugins/aegis.mfa/include/webauthn.login.begin.php',
    '/plugins/aegis.mfa/include/webauthn.login.finish.php',
];
foreach ($WEBAUTHN_PATHS as $wp) {
    $_SERVER['REQUEST_URI'] = $wp;
    t("enrolled unverified, webauthn endpoint allowed: $wp", aegis_mfa_passed() === true);
}
foreach ([$WEBAUTHN_PATHS[0] . '.evil', $WEBAUTHN_PATHS[0] . 'x', '/x' . $WEBAUTHN_PATHS[0],
          '/plugins/aegis.mfa/include/webauthn.enroll.begin.phpx',
          '/plugins/aegis.mfa/webauthn.enroll.begin.php'] as $bad) {
    $_SERVER['REQUEST_URI'] = $bad;
    t("webauthn path trick gated: $bad", aegis_mfa_passed() === false);
}

foreach ([$SETUP . '.evil', $SETUP . '/x', '/x' . $SETUP,
          '/plugins/aegis.mfa/include/setup.phpx', '/plugins/aegis.mfa/setup.php', '/' . $SETUP] as $bad) {
    $_SERVER['REQUEST_URI'] = $bad;
    t("path trick gated: $bad", aegis_mfa_passed() === false);
}

set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
$_SERVER['REQUEST_URI'] = $SETUP;
t('pending unnudged, setup url -> allow', aegis_mfa_passed() === true);

unset($_SERVER['REQUEST_URI']);

set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');

$_SERVER['REQUEST_URI'] = '/Dashboard';
t('enrolled unverified, dashboard -> challenge', aegis_mfa_passed() === false);

// the settings page carries the Disable button, so it is gated like anything else
foreach (['/Settings/AegisMfa', '/plugins/aegis.mfa/AegisMfa.page',
          '/Settings/AegisMfa?foo=1'] as $bad) {
    $_SERVER['REQUEST_URI'] = $bad;
    t("settings url gated: $bad", aegis_mfa_passed() === false);
}
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['amfa_action' => 'toggle', 'enabled' => '0'];
$_SERVER['REQUEST_URI'] = '/Settings/AegisMfa';
t('settings POST gated', aegis_mfa_passed() === false);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_POST = [];

// the wizard stays exempt or a pending user loops between /login and the challenge
$_SERVER['REQUEST_URI'] = '/plugins/aegis.mfa/include/setup.php';
t('setup url still allowed', aegis_mfa_passed() === true);

// fully enforcing is the branch that unconditionally denies an enrolled-unverified session - exactly where the webauthn endpoints must stay reachable
foreach ($WEBAUTHN_PATHS as $wp) {
    $_SERVER['REQUEST_URI'] = $wp;
    t("enforcing, webauthn endpoint still allowed: $wp", aegis_mfa_passed() === true);
}

set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
$_SERVER['REQUEST_URI'] = '/Settings/AegisMfa';
t('pending unnudged, settings url -> nudge', aegis_mfa_passed() === false);
unset($_SERVER['REQUEST_URI']);

set_config(['enabled' => true, 'enforce_after' => 0]);
file_put_contents(AEGIS_MFA_FLASH_DIR . '/secrets.json', '{corrupt');
login_as('root');
t('corrupt secrets -> allow', aegis_mfa_passed() === true);

file_put_contents(AEGIS_MFA_FLASH_DIR . '/config.json', 'not json');
aegis_mfa_config(true);
login_as('root');
t('corrupt config -> allow', aegis_mfa_passed() === true);

set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => 'this-should-be-an-array']]);
login_as('root');
t('malformed user entry -> allow', aegis_mfa_passed() === true);

set_config(['enabled' => true, 'enforce_after' => 0,
    'lockout' => ['threshold' => 3, 'window_seconds' => 300, 'lock_seconds' => 600]]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
$_SERVER['REMOTE_ADDR'] = '203.0.113.60';

$res = aegis_mfa_verify_submission('root', ref_code(0));
t('verify correct code', ($res['ok'] ?? false) === true);
t('verify marks session', aegis_mfa_session_verified() === true);
t('verify reports app code', ($res['method'] ?? '') === 'app code');

t('gate passes after verify', aegis_mfa_passed() === true);

login_as('root');
$res = aegis_mfa_verify_submission('root', '000000');
t('verify wrong not ok', ($res['ok'] ?? true) === false);
t('verify wrong remaining', ($res['remaining'] ?? 0) === 2);

set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
aegis_mfa_clear_failures('203.0.113.60');
$res = aegis_mfa_verify_submission('root', ref_code(-1));
t('verify prev-step code', ($res['ok'] ?? false) === true);

set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
aegis_mfa_clear_failures('203.0.113.60');
$code = ref_code(0);
$r1 = aegis_mfa_verify_submission('root', $code);
t('replay first accepted', ($r1['ok'] ?? false) === true);

login_as('root');
$r2 = aegis_mfa_verify_submission('root', $code);
t('replay second rejected', ($r2['ok'] ?? true) === false);

// which credential was used has to be distinguishable, a backup code is a recovery event
list($bkPlain, $bkHashed) = aegis_mfa_generate_backup_codes(4);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET,
    'backup_codes' => $bkHashed, 'backup_codes_used' => []]]]);
login_as('root');
aegis_mfa_clear_failures('203.0.113.60');
$rb = aegis_mfa_verify_submission('root', $bkPlain[2]);
t('backup code accepted',      ($rb['ok'] ?? false) === true);
t('verify reports backup code', ($rb['method'] ?? '') === 'backup code');
t('backup count drops by one', aegis_mfa_backup_codes_remaining('root') === 3);

login_as('root');
$rb2 = aegis_mfa_verify_submission('root', $bkPlain[2]);
t('spent backup rejected',      ($rb2['ok'] ?? true) === false);
t('spent backup does not count', aegis_mfa_backup_codes_remaining('root') === 3);

login_as('root');
aegis_mfa_clear_failures('203.0.113.60');
$rt = aegis_mfa_verify_submission('root', ref_code(0));
t('app code leaves backups alone', ($rt['ok'] ?? false) === true
    && aegis_mfa_backup_codes_remaining('root') === 3);

set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
$ip = '198.51.100.80';
$_SERVER['REMOTE_ADDR'] = $ip;
aegis_mfa_clear_failures($ip);
$a = aegis_mfa_verify_submission('root', '000000');
$b = aegis_mfa_verify_submission('root', '000000');
$c = aegis_mfa_verify_submission('root', '000000');
t('lock fail1 remaining 2', ($a['remaining'] ?? 0) === 2);
t('lock fail2 remaining 1', ($b['remaining'] ?? 0) === 1);
t('lock fail3 locked',      ($c['locked'] ?? false) === true);
t('lock retry_after > 0',   ($c['retry_after'] ?? 0) > 0);

$d = aegis_mfa_verify_submission('root', ref_code(0));
t('correct code while locked', ($d['locked'] ?? false) === true);

list($plain, $hashed) = aegis_mfa_generate_backup_codes(10);
t('backup gen count',   count($plain) === 10 && count($hashed) === 10);
t('backup gen format',  (bool)preg_match('/^[0-9a-f]{5}-[0-9a-f]{5}$/', $plain[0]));
t('backup gen hashed',  str_starts_with($hashed[0], '$2y$'));
t('backup gen unique',  count(array_unique($plain)) === 10);

t('shape dashed',       aegis_mfa_looks_like_backup_code('abcde-12345') === true);
t('shape nodash',       aegis_mfa_looks_like_backup_code('abcde12345') === true);
t('shape uppercase',    aegis_mfa_looks_like_backup_code('ABCDE-12345') === true);
t('shape totp not bkp', aegis_mfa_looks_like_backup_code('123456') === false);
t('shape too short',    aegis_mfa_looks_like_backup_code('abc-123') === false);
t('shape non-hex',      aegis_mfa_looks_like_backup_code('ghijk-lmnop') === false);

set_secrets(['users' => ['root' => [
    'status' => 'enrolled', 'secret' => $REF_SECRET,
    'backup_codes' => $hashed, 'backup_codes_used' => [],
]]]);
login_as('root');
$ip = '203.0.113.90';
$_SERVER['REMOTE_ADDR'] = $ip;
aegis_mfa_clear_failures($ip);
t('backup remaining 10', aegis_mfa_backup_codes_remaining('root') === 10);

$res = aegis_mfa_verify_submission('root', $plain[3]);
t('backup code accepted', ($res['ok'] ?? false) === true);
t('backup marks verified', aegis_mfa_session_verified() === true);
t('backup remaining 9',   aegis_mfa_backup_codes_remaining('root') === 9);

login_as('root');
$res = aegis_mfa_verify_submission('root', $plain[3]);
t('backup no reuse', ($res['ok'] ?? true) === false);

login_as('root');
aegis_mfa_clear_failures($ip);
$res = aegis_mfa_verify_submission('root', $plain[7]);
t('backup other code works', ($res['ok'] ?? false) === true);
t('backup remaining 8',      aegis_mfa_backup_codes_remaining('root') === 8);

login_as('root');
aegis_mfa_clear_failures($ip);
$res = aegis_mfa_verify_submission('root', 'fffff-fffff');
t('backup wrong code fails', ($res['ok'] ?? true) === false);

aegis_mfa_clear_failures('192.0.2.200');
set_config(['enabled' => true, 'enforce_after' => 0,
    'lockout' => ['threshold' => 1, 'window_seconds' => 300, 'lock_seconds' => 600]]);
aegis_mfa_record_failure('192.0.2.200', 'root', 1000);
t('lock_remaining positive', aegis_mfa_lock_remaining('192.0.2.200', 1000) === 600);
t('lock_remaining decays',   aegis_mfa_lock_remaining('192.0.2.200', 1300) === 300);
t('lock_remaining zero past', aegis_mfa_lock_remaining('192.0.2.200', 2000) === 0);
t('lock_remaining unknown ip', aegis_mfa_lock_remaining('192.0.2.222', 1000) === 0);

echo "\ngate.test.php: {$pass} passed, {$fail} failed\n";
foreach (glob("$work/flash/*") as $g) @unlink($g);
foreach (glob("$work/state/*") as $g) @unlink($g);
foreach (glob("$work/sess_*") as $g) @unlink($g);
@rmdir("$work/flash"); @rmdir("$work/state"); @rmdir($work);
exit($fail === 0 ? 0 : 1);
