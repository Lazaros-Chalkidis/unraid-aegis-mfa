<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/strict.php';

// patch, lint, rollback and reconcile against fixture files. run: php tests/install.test.php

$work = sys_get_temp_dir() . '/aegis-mfa-install-' . getmypid();
$emhttp = $work . '/emhttp';
@mkdir($emhttp . '/webGui/include', 0700, true);
@mkdir($work . '/flash', 0700, true);

define('AEGIS_MFA_EMHTTP', $emhttp);
define('AEGIS_MFA_FLASH_DIR', $work . '/flash');
define('AEGIS_MFA_STATE_DIR', $work . '/state');
define('AEGIS_MFA_NOTIFY_BIN', $work . '/notify');

define('AEGIS_MFA_GATE_PATH', dirname(__DIR__) . '/source/include/AegisMfaGate.php');

require __DIR__ . '/../source/include/AegisMfaInstall.php';

$pass = 0; $fail = 0;
function t(string $name, bool $ok): void {
    global $pass, $fail;
    if ($ok) { $pass++; return; }
    $fail++;
    echo "FAIL  $name\n";
}

$AUTH  = $emhttp . '/auth-request.php';
$LOGIN = $emhttp . '/webGui/include/.login.php';
$FX    = __DIR__ . '/fixtures';

function reset_files(): void {
    global $AUTH, $LOGIN, $FX;
    copy("$FX/auth-request.vanilla.php", $AUTH);
    copy("$FX/login.vanilla.php", $LOGIN);
    @unlink($AUTH . '.aegis-bak');
    @unlink($LOGIN . '.aegis-bak');
}

function enable_mfa(bool $on): void {
    aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => $on]);
    aegis_mfa_config(true);
}

reset_files();

t('fixtures lint clean', aegis_mfa_php_lint($AUTH) && aegis_mfa_php_lint($LOGIN));
t('php cli is not fpm', strpos(basename(aegis_mfa_php_cli()), 'fpm') === false);
t('not patched initially', !aegis_mfa_is_patched($AUTH) && !aegis_mfa_is_patched($LOGIN));
t('may patch recognised', aegis_mfa_may_patch($AUTH) && aegis_mfa_may_patch($LOGIN));

$res = aegis_mfa_install();
t('install ok', ($res['ok'] ?? false) === true);
t('install state patched', ($res['state'] ?? '') === 'patched');
t('auth now patched',  aegis_mfa_is_patched($AUTH));
t('login now patched', aegis_mfa_is_patched($LOGIN));
t('patched auth lints', aegis_mfa_php_lint($AUTH));
t('patched login lints', aegis_mfa_php_lint($LOGIN));
t('backups created', is_file($AUTH . '.aegis-bak') && is_file($LOGIN . '.aegis-bak'));
t('no temp litter',  !is_file($AUTH . '.aegis-tmp') && !is_file($LOGIN . '.aegis-tmp'));

$authbody = file_get_contents($AUTH);
t('hook calls aegis_mfa_passed', strpos($authbody, 'aegis_mfa_passed()') !== false);
t('hook is fail-open guarded', strpos($authbody, 'is_file($aegis_gate)') !== false
                            && strpos($authbody, 'catch (\\Throwable') !== false);

$res2 = aegis_mfa_install();
t('install idempotent', ($res2['ok'] ?? false) === true);
$state = aegis_mfa_patch_state();
t('patch_state full', $state['state'] === 'full' && $state['patched'] === 2);

$res3 = aegis_mfa_uninstall();
t('uninstall ok', ($res3['ok'] ?? false) === true);
t('auth unpatched',  !aegis_mfa_is_patched($AUTH));
t('login unpatched', !aegis_mfa_is_patched($LOGIN));
t('auth restored byte-exact',  hash_file('sha256', $AUTH)  === hash_file('sha256', "$FX/auth-request.vanilla.php"));
t('login restored byte-exact', hash_file('sha256', $LOGIN) === hash_file('sha256', "$FX/login.vanilla.php"));
t('backups removed', !is_file($AUTH . '.aegis-bak') && !is_file($LOGIN . '.aegis-bak'));

t('uninstall idempotent', (aegis_mfa_uninstall()['ok'] ?? false) === true);

reset_files();
t('structure alone decides patching', aegis_mfa_may_patch($AUTH) && aegis_mfa_may_patch($LOGIN));
$res = aegis_mfa_install();
t('installs on structure alone', ($res['ok'] ?? false) === true);
t('both patched',            aegis_mfa_patch_state()['state'] === 'full');
aegis_mfa_uninstall();

reset_files();
$body = file_get_contents($AUTH);
$body = "<?php\n// Unraid 7.4.0 - some new comment\n" . substr($body, 6);
$body = str_replace('$docroot = \'/usr/local/emhttp\';',
                    "\$docroot = '/usr/local/emhttp';\nfunction brandNewHelper() { return 1; }", $body);
file_put_contents($AUTH, $body);
t('unseen version differs',  hash_file('sha256', $AUTH) !== hash_file('sha256', "$FX/auth-request.vanilla.php"));
t('unseen version may patch', aegis_mfa_may_patch($AUTH));
$res = aegis_mfa_install();
t('unseen version installs', ($res['ok'] ?? false) === true);
t('unseen version patched',  aegis_mfa_is_patched($AUTH));
t('unseen still lints',      aegis_mfa_php_lint($AUTH));
aegis_mfa_uninstall();


$spec = aegis_mfa_patch_specs()['auth'];

reset_files();
file_put_contents($AUTH, str_replace(
    "    session_write_close();\n    http_response_code(200);\n    exit;",
    "    session_write_close(); http_response_code(200); exit;", file_get_contents($AUTH)));
t('anchor missing detected', aegis_mfa_structure_ok($spec) === 'anchor_missing');
t('anchor missing refuses',  !aegis_mfa_may_patch($AUTH));
$res = aegis_mfa_install();
t('install refuses anchorless', ($res['ok'] ?? true) === false);
t('refusal names cause', strpos($res['reason'] ?? '', 'anchor_missing') === 0);
t('file untouched', strpos(file_get_contents($AUTH), 'AEGIS_MFA_HOOK') === false);

reset_files();
file_put_contents($AUTH, str_replace('$_SESSION["unraid_login"]', '$_SESSION["something_else"]',
    file_get_contents($AUTH)));
t('signature missing detected', aegis_mfa_structure_ok($spec) === 'signature_missing');
t('signature missing refuses',  !aegis_mfa_may_patch($AUTH));

reset_files();
$dup = file_get_contents($AUTH);
$dup .= "\nfunction dupe() {\n    session_write_close();\n    http_response_code(200);\n    exit;\n}\n";
file_put_contents($AUTH, $dup);
t('anchor ambiguous detected', aegis_mfa_structure_ok($spec) === 'anchor_ambiguous');
t('anchor ambiguous refuses',  !aegis_mfa_may_patch($AUTH));

reset_files();
file_put_contents($AUTH, "<?php\n// AEGIS_MFA_HOOK_BEGIN stale\n" . substr(file_get_contents($AUTH), 6));
t('forbidden marker detected', aegis_mfa_structure_ok($spec) === 'already_patched');

reset_files();
file_put_contents($AUTH, file_get_contents($AUTH) . "\nthis is not php {{{\n");
t('invalid php detected', aegis_mfa_structure_ok($spec) === 'invalid_php');
t('invalid php refuses',  !aegis_mfa_may_patch($AUTH));

reset_files();
unlink($AUTH);
t('missing file detected', aegis_mfa_structure_ok($spec) === 'missing');
$res = aegis_mfa_install();
t('install refuses missing', ($res['ok'] ?? true) === false);

reset_files();
$before = file_get_contents($AUTH);
$badSpec = [
    'path'   => $AUTH,
    'anchor' => "    session_write_close();\n    http_response_code(200);\n    exit;",
    'hook'   => "    // AEGIS_MFA_HOOK_BEGIN\n    this is not php {{{ \n    // AEGIS_MFA_HOOK_END\n",
];
$r = aegis_mfa_patch_file($badSpec);
t('bad patch returns false', $r === false);
t('bad patch rolled back', file_get_contents($AUTH) === $before);
t('bad patch left no marker', strpos(file_get_contents($AUTH), 'AEGIS_MFA_HOOK') === false);
t('bad patch cleaned backup', !is_file($AUTH . '.aegis-bak'));
t('bad patch no temp litter', !is_file($AUTH . '.aegis-tmp'));

reset_files();

file_put_contents($LOGIN, str_replace(
    "    if (\$_SESSION && !empty(\$_SESSION['unraid_user'])) {",
    "    if (false) {", file_get_contents($LOGIN)));
$res = aegis_mfa_install();
t('atomic install fails', ($res['ok'] ?? true) === false);
t('atomic auth NOT left patched', !aegis_mfa_is_patched($AUTH));
t('atomic no half-state', aegis_mfa_patch_state()['state'] === 'none');

reset_files();
$lspec = aegis_mfa_patch_specs()['login'];
t('fixture has two redirects', substr_count(file_get_contents($LOGIN), 'header("Location: /" . $start_page)') === 2);
t('anchor is unique',     substr_count(file_get_contents($LOGIN), $lspec['anchor']) === 1);
t('two-redirect structure ok', aegis_mfa_structure_ok($lspec) === '');
t('two-redirect patches', aegis_mfa_patch_file($lspec) === true);
t('patched exactly once', substr_count(file_get_contents($LOGIN), 'AEGIS_MFA_HOOK_BEGIN') === 1);
t('two-redirect lints', aegis_mfa_php_lint($LOGIN));

$body = file_get_contents($LOGIN);
t('hook before first redirect',
    strpos($body, 'AEGIS_MFA_HOOK_BEGIN') < strpos($body, 'header("Location: /" . $start_page)'));
aegis_mfa_unpatch_file($lspec);
t('two-redirect unpatch clean', strpos(file_get_contents($LOGIN), 'AEGIS_MFA_HOOK') === false);

reset_files();
enable_mfa(true);
$r = aegis_mfa_reconcile_patches();
t('reconcile enabled patches', ($r['ok'] ?? false) === true && aegis_mfa_is_patched($AUTH));

enable_mfa(false);
$r = aegis_mfa_reconcile_patches();
t('reconcile disabled unpatches', ($r['ok'] ?? false) === true && !aegis_mfa_is_patched($AUTH));

reset_files();
enable_mfa(true);
aegis_mfa_reconcile_patches();
t('reconcile patched pre-flag', aegis_mfa_is_patched($AUTH));
touch(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');
$r = aegis_mfa_reconcile_patches();
t('rescue flag unpatches', !aegis_mfa_is_patched($AUTH));
unlink(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');

reset_files();
enable_mfa(true);
aegis_mfa_reconcile_patches();
t('pre-update patched', aegis_mfa_is_patched($AUTH));

copy("$FX/auth-request.vanilla.php", $AUTH);
t('update removed patch', !aegis_mfa_is_patched($AUTH));
t('but login still patched (half)', aegis_mfa_is_patched($LOGIN));
t('state is partial now', aegis_mfa_patch_state()['state'] === 'partial');

$r = aegis_mfa_reconcile_patches();
t('reconcile re-patches auth', aegis_mfa_is_patched($AUTH));
t('healed to full', aegis_mfa_patch_state()['state'] === 'full');

reset_files();
enable_mfa(true);
aegis_mfa_reconcile_patches();

file_put_contents($AUTH, "<?php\n// brand new unraid auth, unknown layout\nhttp_response_code(200);\n");
t('update to unknown wipes auth patch', !aegis_mfa_is_patched($AUTH));
t('login patch survives', aegis_mfa_is_patched($LOGIN));

$r = aegis_mfa_reconcile_patches();
t('reconcile refuses broken structure', ($r['ok'] ?? true) === false);
t('reconcile removed surviving patch', !aegis_mfa_is_patched($LOGIN));
t('uniformly unpatched (fail-open)', aegis_mfa_patch_state()['state'] === 'none');


$NLOG = $work . '/notify.log';
file_put_contents(AEGIS_MFA_NOTIFY_BIN, "#!/bin/sh\necho \"\$@\" >> " . escapeshellarg($NLOG) . "\n");
chmod(AEGIS_MFA_NOTIFY_BIN, 0755);
@unlink($NLOG);
@unlink(AEGIS_MFA_STATE_DIR . '/notify.stamp');

reset_files();
enable_mfa(true);
aegis_mfa_notify_patch_state();
$log = @file($NLOG) ?: [];
t('notify alert fired once', count($log) === 1 && strpos($log[0], '-i alert') !== false);
t('notify stamp written',    is_file(AEGIS_MFA_STATE_DIR . '/notify.stamp'));
aegis_mfa_notify_patch_state();
t('notify de-duped', count(@file($NLOG) ?: []) === 1);

$res = aegis_mfa_install();
t('notify precondition patched', ($res['ok'] ?? false) === true);
aegis_mfa_notify_patch_state();
$log = @file($NLOG) ?: [];
t('notify all-clear fired',  count($log) === 2 && strpos($log[1], 'restored') !== false);
t('notify stamp cleared',    !is_file(AEGIS_MFA_STATE_DIR . '/notify.stamp'));
aegis_mfa_notify_patch_state();
t('notify quiet when healthy', count(@file($NLOG) ?: []) === 2);

aegis_mfa_uninstall();
aegis_mfa_notify_patch_state();
t('notify re-alerts new incident', count(@file($NLOG) ?: []) === 3);

enable_mfa(false);
aegis_mfa_notify_patch_state();
t('notify silent on disable',        count(@file($NLOG) ?: []) === 3);
t('notify stamp cleared on disable', !is_file(AEGIS_MFA_STATE_DIR . '/notify.stamp'));

reset_files();
enable_mfa(false);
$pfa = md5_file($AUTH); $pfl = md5_file($LOGIN);
$pf = aegis_mfa_preflight();
t('preflight passes on vanilla', ($pf['ok'] ?? false) === true);
t('preflight live untouched', md5_file($AUTH) === $pfa && md5_file($LOGIN) === $pfl);
$names = array_column($pf['checks'], 'name');
t('preflight ran both rehearsals', count(preg_grep('/^rehearsal:/', $names)) === 2);
t('preflight left no temp litter', glob(sys_get_temp_dir() . '/aegis-mfa-preflight-*') === []);

file_put_contents($AUTH, str_replace('session_write_close();', 'session_wc();', file_get_contents($AUTH)));
$pfa = md5_file($AUTH);
$pf = aegis_mfa_preflight();
t('preflight fails on broken anchor', ($pf['ok'] ?? true) === false);
$badnames = [];
foreach ($pf['checks'] as $c) { if (!$c['ok']) $badnames[] = $c['name'] . '=' . $c['detail']; }
t('preflight names the reason', strpos(implode(',', $badnames), 'anchor_missing') !== false);
t('preflight broken file untouched', md5_file($AUTH) === $pfa);
reset_files();

enable_mfa(true);
aegis_mfa_install();
$pf = aegis_mfa_preflight();
t('preflight ok when patched', ($pf['ok'] ?? false) === true);
t('preflight skips rehearsal when patched',
    count(preg_grep('/^rehearsal:/', array_column($pf['checks'], 'name'))) === 0);
aegis_mfa_uninstall();
enable_mfa(false);

file_put_contents(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag', '1');
$pf = aegis_mfa_preflight();
t('preflight flags stale DISABLE.flag', ($pf['ok'] ?? true) === false);
@unlink(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');

reset_files();
enable_mfa(true);
aegis_mfa_install();
$specs = aegis_mfa_patch_specs();
t('fresh patch is current', aegis_mfa_hook_current($specs['auth']) && aegis_mfa_hook_current($specs['login']));

$body = file_get_contents($AUTH);
$stale = preg_replace(
    '/(AEGIS_MFA_HOOK_BEGIN).*?(\/\/ AEGIS_MFA_HOOK_END)/s',
    "$1\n    \$x = 1;  // hook from an older release\n    $2",
    $body, 1);
file_put_contents($AUTH, $stale);
t('stale hook still has markers', aegis_mfa_is_patched($AUTH));
t('stale hook detected',          !aegis_mfa_hook_current($specs['auth']));
t('stale hook: other file fine',  aegis_mfa_hook_current($specs['login']));

$res = aegis_mfa_reconcile_patches();
t('upgrade reconcile ok',      ($res['ok'] ?? false) === true);
t('stale hook refreshed',      aegis_mfa_hook_current($specs['auth']));
t('refreshed file lints',      aegis_mfa_php_lint($AUTH));
t('old hook body gone',        strpos(file_get_contents($AUTH), 'older release') === false);
t('refresh kept one hook',     substr_count(file_get_contents($AUTH), 'AEGIS_MFA_HOOK_BEGIN') === 1);
t('refresh left backup',       is_file($AUTH . '.aegis-bak'));
t('refresh no temp litter',    !is_file($AUTH . '.aegis-tmp'));

aegis_mfa_uninstall();
t('refreshed file restores clean', file_get_contents($AUTH) === file_get_contents("$FX/auth-request.vanilla.php"));
enable_mfa(false);
reset_files();
echo "\ninstall.test.php: {$pass} passed, {$fail} failed\n";

exec('rm -rf ' . escapeshellarg($work));
exit($fail === 0 ? 0 : 1);
