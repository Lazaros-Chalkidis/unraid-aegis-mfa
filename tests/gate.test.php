<?php
/*
 * Aegis MFA - gate test suite
 * run: php tests/gate.test.php
 * exit 0 on full pass, 1 on any failure
 */

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

// helpers to shape the world for each case
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
    // a fresh browser login lands as a top-level GET navigation
    $_SERVER['REQUEST_METHOD']       = 'GET';
    $_SERVER['HTTP_SEC_FETCH_DEST']  = 'document';
    unset($_SERVER['HTTP_ACCEPT'], $_POST);
    $_POST = [];
}
function logout(): void { $_SESSION = []; }

$REF_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';   // decodes to the RFC test key
$REF_RAW    = '12345678901234567890';
function ref_code(int $offset = 0): string {
    global $REF_RAW;
    return aegis_totp_hotp($REF_RAW, intdiv(time(), 30) + $offset);
}

aegis_mfa_session_ensure();
$_SERVER['REMOTE_ADDR'] = '203.0.113.50';   // not in any trust range

// GATE DECISION MATRIX

// plugin disabled -> allow regardless of everything else
set_config(['enabled' => false]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
t('disabled -> allow', aegis_mfa_passed() === true);

// USB rescue flag -> allow even when enabled
set_config(['enabled' => true, 'enforce_after' => 0]);
touch(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');
t('rescue flag -> allow', aegis_mfa_passed() === true);
unlink(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');

// no logged-in user -> allow (not our job)
set_config(['enabled' => true, 'enforce_after' => 0]);
logout();
t('no session -> allow', aegis_mfa_passed() === true);

// user status 'none' -> allow
set_secrets(['users' => []]);
login_as('root');
t('status none -> allow', aegis_mfa_passed() === true);

// 'pending' (in grace): bounced once, allowed after the nudge
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
t('pending unnudged -> challenge', aegis_mfa_passed() === false);
aegis_mfa_mark_nudged('root');
t('pending nudged -> allow', aegis_mfa_passed() === true);

// nudge is per user: a switch inside the same session re-prompts
$_SESSION['unraid_user'] = 'lazaros';
set_secrets(['users' => [
    'root'    => ['status' => 'pending', 'grace_until' => time() + 3600],
    'lazaros' => ['status' => 'pending', 'grace_until' => time() + 3600],
]]);
t('pending nudge other user -> challenge', aegis_mfa_passed() === false);

// the nudge bounces ONLY top-level navigations. Assets, XHR and pollers
// of an open tab must pass, or each becomes a /login redirect and floods
// the nginx authlimit zone.
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';   // XHR / fetch
t('pending unnudged, xhr -> allow', aegis_mfa_passed() === true);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'style';   // stylesheet
t('pending unnudged, asset -> allow', aegis_mfa_passed() === true);
$_SERVER['REQUEST_METHOD'] = 'POST';         // a form submit elsewhere
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
t('pending unnudged, plain post -> allow', aegis_mfa_passed() === true);
$_POST['aegis_mfa_code'] = '123456';         // but our code post reaches the view
t('pending unnudged, code post -> challenge', aegis_mfa_passed() === false);
$_POST = [];

// fetch metadata absent (old client): Accept decides, ambiguity passes
login_as('root');
unset($_SERVER['HTTP_SEC_FETCH_DEST']);
$_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml';
t('pending unnudged, legacy html get -> challenge', aegis_mfa_passed() === false);
$_SERVER['HTTP_ACCEPT'] = 'application/json';
t('pending unnudged, legacy json get -> allow', aegis_mfa_passed() === true);
login_as('root');   // restore navigation defaults for what follows

// enrolled, enforcing, not LAN, not verified -> CHALLENGE
set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
t('enrolled unverified -> challenge', aegis_mfa_passed() === false);
// hard enforcement is not softened by the request type: an unverified
// session gets 401 on XHR too, that IS the protection
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';
t('enrolled unverified, xhr -> challenge', aegis_mfa_passed() === false);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';

// same, but trusted LAN -> allow
set_config(['enabled' => true, 'enforce_after' => 0, 'trust_lan' => ['203.0.113.0/24']]);
login_as('root');
t('enrolled + LAN -> allow', aegis_mfa_passed() === true);
set_config(['enabled' => true, 'enforce_after' => 0]);   // drop LAN again

// same, but session already verified -> allow
login_as('root');
aegis_mfa_mark_verified('root');
t('enrolled + verified -> allow', aegis_mfa_passed() === true);

// verified as a DIFFERENT user -> challenge (switch guard)
$_SESSION['unraid_user'] = 'lazaros';
set_secrets(['users' => [
    'root'    => ['status' => 'enrolled', 'secret' => $REF_SECRET],
    'lazaros' => ['status' => 'enrolled', 'secret' => $REF_SECRET],
]]);
t('verified other user -> challenge', aegis_mfa_passed() === false);

// dry-run window: bounced once so the prompt is seen, never blocks --
set_config(['enabled' => true, 'enforce_after' => time() + 3600]);
login_as('root');
t('dry-run unnudged -> challenge', aegis_mfa_passed() === false);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'empty';
t('dry-run unnudged, xhr -> allow', aegis_mfa_passed() === true);
$_SERVER['HTTP_SEC_FETCH_DEST'] = 'document';
aegis_mfa_mark_nudged('root');
t('dry-run nudged -> allow', aegis_mfa_passed() === true);

// dry-run covers 'locked' too: an expired grace must not hard-block
// before enforcement begins, the skip on the setup screen lets them on
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() - 10]]]);
login_as('root');
t('dry-run locked unnudged -> challenge', aegis_mfa_passed() === false);
aegis_mfa_mark_nudged('root');
t('dry-run locked nudged -> allow', aegis_mfa_passed() === true);

// grace expired -> 'locked' -> challenge, nudge does NOT unlock
set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() - 10]]]);
login_as('root');
t('grace expired -> challenge', aegis_mfa_passed() === false);
aegis_mfa_mark_nudged('root');
t('grace expired + nudge -> still challenge', aegis_mfa_passed() === false);
login_as('root');   // drop the nudge before the setup-url block below

// SETUP ENDPOINT PASS-THROUGH
// the wizard must stay reachable for locked users and token holders,
// and for nothing else. exact path match only.
$SETUP = '/plugins/aegis.mfa/include/setup.php';

// locked user: any other URL is challenged, the wizard is not
login_as('root');
$_SERVER['REQUEST_URI'] = '/Dashboard';
t('locked, other url -> challenge', aegis_mfa_passed() === false);
$_SERVER['REQUEST_URI'] = $SETUP;
t('locked, setup url -> allow', aegis_mfa_passed() === true);
$_SERVER['REQUEST_URI'] = $SETUP . '?user=root&token=abc';
t('locked, setup url + query -> allow', aegis_mfa_passed() === true);

// enrolled + unverified (the lost-authenticator token path): same shape
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
$_SERVER['REQUEST_URI'] = '/Main';
t('enrolled unverified, other url -> challenge', aegis_mfa_passed() === false);
$_SERVER['REQUEST_URI'] = $SETUP;
t('enrolled unverified, setup url -> allow', aegis_mfa_passed() === true);

// path tricks stay gated: suffix, prefix, traversal, protocol-relative
foreach ([$SETUP . '.evil', $SETUP . '/x', '/x' . $SETUP,
          '/plugins/aegis.mfa/include/setup.phpx', '/plugins/aegis.mfa/setup.php', '/' . $SETUP] as $bad) {
    $_SERVER['REQUEST_URI'] = $bad;
    t("path trick gated: $bad", aegis_mfa_passed() === false);
}

// a pending user reaches the wizard through the setup-url rule even
// before the first bounce: an admin-sent setup link opened cold must
// not 401 into the challenge loop
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
$_SERVER['REQUEST_URI'] = $SETUP;
t('pending unnudged, setup url -> allow', aegis_mfa_passed() === true);

unset($_SERVER['REQUEST_URI']);

// OWN SETTINGS PAGE PASS-THROUGH
// the admin must always reach the plugin's own controls, or turning
// MFA off is blocked by MFA. This is the enable-then-disable race:
// an enrolled, unverified admin POSTing Disable would be 401'd.
set_config(['enabled' => true, 'enforce_after' => 0]);   // enforcing
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');

// baseline: any other protected URL is still challenged for this user
$_SERVER['REQUEST_URI'] = '/Dashboard';
t('enrolled unverified, dashboard -> challenge', aegis_mfa_passed() === false);

// the settings page and its toggle POST land here and must pass
foreach (['/Settings/AegisMfa', '/plugins/aegis.mfa/AegisMfa.page'] as $ok) {
    $_SERVER['REQUEST_URI'] = $ok;
    t("settings url allowed: $ok", aegis_mfa_passed() === true);
}
$_SERVER['REQUEST_URI'] = '/Settings/AegisMfa?foo=1';
t('settings url + query allowed', aegis_mfa_passed() === true);

// a pending admin before the first bounce must reach them too, or the
// account that just enabled MFA is bounced off its own settings page
set_secrets(['users' => ['root' => ['status' => 'pending', 'grace_until' => time() + 3600]]]);
login_as('root');
$_SERVER['REQUEST_URI'] = '/Settings/AegisMfa';
t('pending unnudged, settings url -> allow', aegis_mfa_passed() === true);

// path tricks around the settings URL stay gated
foreach (['/Settings/AegisMfaX', '/Settings/AegisMfa/../Dashboard',
          '/x/Settings/AegisMfa', '/plugins/aegis.mfa/AegisMfa.page.evil'] as $bad) {
    $_SERVER['REQUEST_URI'] = $bad;
    t("settings path trick gated: $bad", aegis_mfa_passed() === false);
}
unset($_SERVER['REQUEST_URI']);

// FAIL-OPEN PATHS  (the whole point of the design)

// secrets.json corrupt -> gate must still allow
set_config(['enabled' => true, 'enforce_after' => 0]);
file_put_contents(AEGIS_MFA_FLASH_DIR . '/secrets.json', '{corrupt');
login_as('root');
t('corrupt secrets -> allow', aegis_mfa_passed() === true);

// config.json corrupt -> defaults (disabled) -> allow
file_put_contents(AEGIS_MFA_FLASH_DIR . '/config.json', 'not json');
aegis_mfa_config(true);
login_as('root');
t('corrupt config -> allow', aegis_mfa_passed() === true);

// flash dir unreadable path -> allow
// simulate by pointing status lookup at a user with a broken structure
set_config(['enabled' => true, 'enforce_after' => 0]);
set_secrets(['users' => ['root' => 'this-should-be-an-array']]);
login_as('root');
t('malformed user entry -> allow', aegis_mfa_passed() === true);

// CHALLENGE VERIFICATION
set_config(['enabled' => true, 'enforce_after' => 0,
    'lockout' => ['threshold' => 3, 'window_seconds' => 300, 'lock_seconds' => 600]]);
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
$_SERVER['REMOTE_ADDR'] = '203.0.113.60';

// correct current code -> ok, and session becomes verified
$res = aegis_mfa_verify_submission('root', ref_code(0));
t('verify correct code', ($res['ok'] ?? false) === true);
t('verify marks session', aegis_mfa_session_verified() === true);

// gate now passes for this session
t('gate passes after verify', aegis_mfa_passed() === true);

// wrong code -> not ok, remaining reported
login_as('root');
$res = aegis_mfa_verify_submission('root', '000000');
t('verify wrong not ok', ($res['ok'] ?? true) === false);
t('verify wrong remaining', ($res['remaining'] ?? 0) === 2);

// code accepted within +/-1 window
// (reset secrets so the replay guard's last_step is clear; the earlier
// successful verify consumed step 0, which would otherwise reject step -1)
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
aegis_mfa_clear_failures('203.0.113.60');
$res = aegis_mfa_verify_submission('root', ref_code(-1));
t('verify prev-step code', ($res['ok'] ?? false) === true);

// REPLAY PROTECTION
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
aegis_mfa_clear_failures('203.0.113.60');
$code = ref_code(0);
$r1 = aegis_mfa_verify_submission('root', $code);
t('replay first accepted', ($r1['ok'] ?? false) === true);
// same code, same step, second time -> rejected (already consumed)
login_as('root');
$r2 = aegis_mfa_verify_submission('root', $code);
t('replay second rejected', ($r2['ok'] ?? true) === false);

// LOCKOUT VIA VERIFICATION
set_secrets(['users' => ['root' => ['status' => 'enrolled', 'secret' => $REF_SECRET]]]);
login_as('root');
$ip = '198.51.100.80';
$_SERVER['REMOTE_ADDR'] = $ip;
aegis_mfa_clear_failures($ip);
$a = aegis_mfa_verify_submission('root', '000000');   // fail 1
$b = aegis_mfa_verify_submission('root', '000000');   // fail 2
$c = aegis_mfa_verify_submission('root', '000000');   // fail 3 -> lock
t('lock fail1 remaining 2', ($a['remaining'] ?? 0) === 2);
t('lock fail2 remaining 1', ($b['remaining'] ?? 0) === 1);
t('lock fail3 locked',      ($c['locked'] ?? false) === true);
t('lock retry_after > 0',   ($c['retry_after'] ?? 0) > 0);
// even a CORRECT code is refused while locked
$d = aegis_mfa_verify_submission('root', ref_code(0));
t('correct code while locked', ($d['locked'] ?? false) === true);

// BACKUP CODES
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

// consume a real backup code end to end
set_secrets(['users' => ['root' => [
    'status' => 'enrolled', 'secret' => $REF_SECRET,
    'backup_codes' => $hashed, 'backup_codes_used' => [],
]]]);
login_as('root');
$ip = '203.0.113.90';
$_SERVER['REMOTE_ADDR'] = $ip;
aegis_mfa_clear_failures($ip);
t('backup remaining 10', aegis_mfa_backup_codes_remaining('root') === 10);

$res = aegis_mfa_verify_submission('root', $plain[3]);   // use the 4th code
t('backup code accepted', ($res['ok'] ?? false) === true);
t('backup marks verified', aegis_mfa_session_verified() === true);
t('backup remaining 9',   aegis_mfa_backup_codes_remaining('root') === 9);

// the same backup code cannot be reused
login_as('root');
$res = aegis_mfa_verify_submission('root', $plain[3]);
t('backup no reuse', ($res['ok'] ?? true) === false);

// a different, unused code still works
login_as('root');
aegis_mfa_clear_failures($ip);
$res = aegis_mfa_verify_submission('root', $plain[7]);
t('backup other code works', ($res['ok'] ?? false) === true);
t('backup remaining 8',      aegis_mfa_backup_codes_remaining('root') === 8);

// wrong backup code (right shape, not in list) -> fail
login_as('root');
aegis_mfa_clear_failures($ip);
$res = aegis_mfa_verify_submission('root', 'fffff-fffff');
t('backup wrong code fails', ($res['ok'] ?? true) === false);

// lock_remaining
aegis_mfa_clear_failures('192.0.2.200');
set_config(['enabled' => true, 'enforce_after' => 0,
    'lockout' => ['threshold' => 1, 'window_seconds' => 300, 'lock_seconds' => 600]]);
aegis_mfa_record_failure('192.0.2.200', 'root', 1000);   // threshold 1 -> instant lock
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
