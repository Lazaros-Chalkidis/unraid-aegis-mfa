<?php
/*
 * Aegis MFA - installer test suite
 * run: php tests/install.test.php
 * exit 0 on full pass, 1 on any failure
 *
 * Works entirely on throwaway copies of the two Unraid file fixtures.
 * Never touches a real system.
 */

$work = sys_get_temp_dir() . '/aegis-mfa-install-' . getmypid();
$emhttp = $work . '/emhttp';
@mkdir($emhttp . '/webGui/include', 0700, true);
@mkdir($work . '/flash', 0700, true);

define('AEGIS_MFA_EMHTTP', $emhttp);
define('AEGIS_MFA_FLASH_DIR', $work . '/flash');
define('AEGIS_MFA_STATE_DIR', $work . '/state');
define('AEGIS_MFA_COMPAT_FILE', $work . '/flash/compat.json');
define('AEGIS_MFA_NOTIFY_BIN', $work . '/notify');
define('AEGIS_MFA_COMPAT_DEFAULT', $work . '/pkg-compat.json');
// the embedded gate path in patches points at the REAL plugin gate so the
// patched files are require-able; existence is all that matters here.
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

// place fresh vanilla copies of both target files.
function reset_files(): void {
    global $AUTH, $LOGIN, $FX;
    copy("$FX/auth-request.vanilla.php", $AUTH);
    copy("$FX/login.vanilla.php", $LOGIN);
    @unlink($AUTH . '.aegis-bak');
    @unlink($LOGIN . '.aegis-bak');
}
// seed compat.json with the fixtures' real vanilla checksums.
function seed_compat(): void {
    global $AUTH, $LOGIN;
    aegis_mfa_write_json(AEGIS_MFA_COMPAT_FILE, ['versions' => ['7.3.1' => [
        'auth'  => hash_file('sha256', $AUTH),
        'login' => hash_file('sha256', $LOGIN),
    ]]], 0644);
}
function enable_mfa(bool $on): void {
    aegis_mfa_write_json(AEGIS_MFA_FLASH_DIR . '/config.json', ['enabled' => $on]);
    aegis_mfa_config(true);
}

// BASIC PATCH / LINT / UNPATCH
reset_files();
seed_compat();

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

// the hook actually contains our call
$authbody = file_get_contents($AUTH);
t('hook calls aegis_mfa_passed', strpos($authbody, 'aegis_mfa_passed()') !== false);
t('hook is fail-open guarded', strpos($authbody, 'is_file($aegis_gate)') !== false
                            && strpos($authbody, 'catch (\\Throwable') !== false);

// install is idempotent
$res2 = aegis_mfa_install();
t('install idempotent', ($res2['ok'] ?? false) === true);
$state = aegis_mfa_patch_state();
t('patch_state full', $state['state'] === 'full' && $state['patched'] === 2);

// unpatch restores vanilla exactly
$res3 = aegis_mfa_uninstall();
t('uninstall ok', ($res3['ok'] ?? false) === true);
t('auth unpatched',  !aegis_mfa_is_patched($AUTH));
t('login unpatched', !aegis_mfa_is_patched($LOGIN));
t('auth restored byte-exact',  hash_file('sha256', $AUTH)  === hash_file('sha256', "$FX/auth-request.vanilla.php"));
t('login restored byte-exact', hash_file('sha256', $LOGIN) === hash_file('sha256', "$FX/login.vanilla.php"));
t('backups removed', !is_file($AUTH . '.aegis-bak') && !is_file($LOGIN . '.aegis-bak'));

// unpatch is idempotent on clean files
t('uninstall idempotent', (aegis_mfa_uninstall()['ok'] ?? false) === true);

// STRUCTURAL GATE (replaces the old checksum whitelist)
// The real safety condition is SHAPE, not bytes: an Unraid release we
// have never seen must still install cleanly if the structure holds.
reset_files();
@unlink(AEGIS_MFA_COMPAT_FILE);          // no compat data at all
t('structure ok, no compat', aegis_mfa_may_patch($AUTH) && aegis_mfa_may_patch($LOGIN));
$res = aegis_mfa_install();
t('installs with no compat', ($res['ok'] ?? false) === true);
t('validated flag false',    ($res['validated'] ?? true) === false);
t('both patched',            aegis_mfa_patch_state()['state'] === 'full');
aegis_mfa_uninstall();

// an UNSEEN Unraid release: same structure, different bytes (a comment
// changed, whitespace, an unrelated function added). Must still patch.
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

// compat.json present and matching -> validated = true (informational)
reset_files();
seed_compat();
t('version validated true', aegis_mfa_version_validated() === true);
$res = aegis_mfa_install();
t('validated reported', ($res['validated'] ?? false) === true);
aegis_mfa_uninstall();

// compat.json present but NOT matching -> still installs, validated = false
reset_files();
aegis_mfa_write_json(AEGIS_MFA_COMPAT_FILE, ['versions' => ['9.9.9' => [
    'auth' => str_repeat('0', 64), 'login' => str_repeat('0', 64),
]]], 0644);
t('unknown sha not validated', aegis_mfa_version_validated() === false);
$res = aegis_mfa_install();
t('unknown sha still installs', ($res['ok'] ?? false) === true);
t('unknown sha validated=false', ($res['validated'] ?? true) === false);
aegis_mfa_uninstall();

// STRUCTURE REFUSALS: each failure mode is caught and reported
$spec = aegis_mfa_patch_specs()['auth'];

// anchor gone (Unraid restructured the success branch) -> refuse
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

// signature gone (it is not the file we think it is) -> refuse
reset_files();
file_put_contents($AUTH, str_replace('$_SESSION["unraid_login"]', '$_SESSION["something_else"]',
    file_get_contents($AUTH)));
t('signature missing detected', aegis_mfa_structure_ok($spec) === 'signature_missing');
t('signature missing refuses',  !aegis_mfa_may_patch($AUTH));

// anchor appears twice (ambiguous insertion point) -> refuse
reset_files();
$dup = file_get_contents($AUTH);
$dup .= "\nfunction dupe() {\n    session_write_close();\n    http_response_code(200);\n    exit;\n}\n";
file_put_contents($AUTH, $dup);
t('anchor ambiguous detected', aegis_mfa_structure_ok($spec) === 'anchor_ambiguous');
t('anchor ambiguous refuses',  !aegis_mfa_may_patch($AUTH));

// someone else's marker present -> refuse
reset_files();
file_put_contents($AUTH, "<?php\n// AEGIS_MFA_HOOK_BEGIN stale\n" . substr(file_get_contents($AUTH), 6));
t('forbidden marker detected', aegis_mfa_structure_ok($spec) === 'already_patched');

// file already invalid PHP -> refuse (no safe rollback target)
reset_files();
file_put_contents($AUTH, file_get_contents($AUTH) . "\nthis is not php {{{\n");
t('invalid php detected', aegis_mfa_structure_ok($spec) === 'invalid_php');
t('invalid php refuses',  !aegis_mfa_may_patch($AUTH));

// missing file -> refuse
reset_files();
unlink($AUTH);
t('missing file detected', aegis_mfa_structure_ok($spec) === 'missing');
$res = aegis_mfa_install();
t('install refuses missing', ($res['ok'] ?? true) === false);

// ROLLBACK: a patch that produces invalid PHP is reverted
reset_files();
seed_compat();
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

// ATOMICITY: if the SECOND file can't be patched, the FIRST is rolled back
reset_files();
seed_compat();
// break .login.php structurally: remove its anchor (the "already logged in"
// test) while auth stays fine. Install must patch nothing.
file_put_contents($LOGIN, str_replace(
    "    if (\$_SESSION && !empty(\$_SESSION['unraid_user'])) {",
    "    if (false) {", file_get_contents($LOGIN)));
$res = aegis_mfa_install();
t('atomic install fails', ($res['ok'] ?? true) === false);
t('atomic auth NOT left patched', !aegis_mfa_is_patched($AUTH));
t('atomic no half-state', aegis_mfa_patch_state()['state'] === 'none');

// REGRESSION (Raptor1): the redirect line appears TWICE in the real .login.php
// (the logged-in branch AND the POST handler), which is why the anchor is the
// unique "already logged in" test, not the redirect. The fixture reproduces
// this. Verify the anchor stays unique and the hook lands in the right block.
reset_files();
$lspec = aegis_mfa_patch_specs()['login'];
t('fixture has two redirects', substr_count(file_get_contents($LOGIN), 'header("Location: /" . $start_page)') === 2);
t('anchor is unique',     substr_count(file_get_contents($LOGIN), $lspec['anchor']) === 1);
t('two-redirect structure ok', aegis_mfa_structure_ok($lspec) === '');
t('two-redirect patches', aegis_mfa_patch_file($lspec) === true);
t('patched exactly once', substr_count(file_get_contents($LOGIN), 'AEGIS_MFA_HOOK_BEGIN') === 1);
t('two-redirect lints', aegis_mfa_php_lint($LOGIN));
// hook landed inside the logged-in branch, above the FIRST redirect only
$body = file_get_contents($LOGIN);
t('hook before first redirect',
    strpos($body, 'AEGIS_MFA_HOOK_BEGIN') < strpos($body, 'header("Location: /" . $start_page)'));
aegis_mfa_unpatch_file($lspec);
t('two-redirect unpatch clean', strpos(file_get_contents($LOGIN), 'AEGIS_MFA_HOOK') === false);

// RECONCILE: enabled -> patched, disabled -> unpatched
reset_files();
seed_compat();
enable_mfa(true);
$r = aegis_mfa_reconcile_patches();
t('reconcile enabled patches', ($r['ok'] ?? false) === true && aegis_mfa_is_patched($AUTH));

enable_mfa(false);
$r = aegis_mfa_reconcile_patches();
t('reconcile disabled unpatches', ($r['ok'] ?? false) === true && !aegis_mfa_is_patched($AUTH));

// USB rescue flag forces unpatch even if config says enabled
reset_files();
seed_compat();
enable_mfa(true);
aegis_mfa_reconcile_patches();
t('reconcile patched pre-flag', aegis_mfa_is_patched($AUTH));
touch(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');
$r = aegis_mfa_reconcile_patches();
t('rescue flag unpatches', !aegis_mfa_is_patched($AUTH));
unlink(AEGIS_MFA_FLASH_DIR . '/DISABLE.flag');

// SIMULATED OS UPDATE: patched file replaced by fresh vanilla, reconcile
// must re-patch it (checksum recognised again).
reset_files();
seed_compat();
enable_mfa(true);
aegis_mfa_reconcile_patches();
t('pre-update patched', aegis_mfa_is_patched($AUTH));
// OS update wipes the patch (restores vanilla)
copy("$FX/auth-request.vanilla.php", $AUTH);
t('update removed patch', !aegis_mfa_is_patched($AUTH));
t('but login still patched (half)', aegis_mfa_is_patched($LOGIN));
t('state is partial now', aegis_mfa_patch_state()['state'] === 'partial');
// reconcile heals back to fully patched
$r = aegis_mfa_reconcile_patches();
t('reconcile re-patches auth', aegis_mfa_is_patched($AUTH));
t('healed to full', aegis_mfa_patch_state()['state'] === 'full');

// SIMULATED OS UPDATE to an UNKNOWN version: reconcile can't re-patch,
// so it must remove the surviving patch (never leave half-wired).
reset_files();
seed_compat();
enable_mfa(true);
aegis_mfa_reconcile_patches();
// update replaces auth with a STRUCTURALLY DIFFERENT file (no anchor)
file_put_contents($AUTH, "<?php\n// brand new unraid auth, unknown layout\nhttp_response_code(200);\n");
t('update to unknown wipes auth patch', !aegis_mfa_is_patched($AUTH));
t('login patch survives', aegis_mfa_is_patched($LOGIN));
// reconcile: can't patch auth (unknown) -> must unpatch login too
$r = aegis_mfa_reconcile_patches();
t('reconcile refuses broken structure', ($r['ok'] ?? true) === false);
t('reconcile removed surviving patch', !aegis_mfa_is_patched($LOGIN));
t('uniformly unpatched (fail-open)', aegis_mfa_patch_state()['state'] === 'none');

// COMPAT CAPTURE
reset_files();
@unlink(AEGIS_MFA_COMPAT_FILE);
$cap = aegis_mfa_capture_compat('7.3.1');
t('capture ok', ($cap['ok'] ?? false) === true);
$compat = aegis_mfa_read_json(AEGIS_MFA_COMPAT_FILE);
t('capture wrote shas', isset($compat['versions']['7.3.1']['auth'], $compat['versions']['7.3.1']['login']));
t('captured sha matches file', $compat['versions']['7.3.1']['auth'] === hash_file('sha256', $AUTH));
// capture makes the version "validated" (informational only)
t('capture marks validated', aegis_mfa_version_validated() === true);
$res = aegis_mfa_install();
t('install works post-capture', ($res['ok'] ?? false) === true);
t('post-capture validated', ($res['validated'] ?? false) === true);
// capture refuses on an already-patched file
$cap2 = aegis_mfa_capture_compat('7.3.2');
t('capture refuses patched', ($cap2['ok'] ?? true) === false);

// ADMIN NOTIFICATION (enabled but unpatched -> one alert per incident)
$NLOG = $work . '/notify.log';
file_put_contents(AEGIS_MFA_NOTIFY_BIN, "#!/bin/sh\necho \"\$@\" >> " . escapeshellarg($NLOG) . "\n");
chmod(AEGIS_MFA_NOTIFY_BIN, 0755);
@unlink($NLOG);
@unlink(AEGIS_MFA_STATE_DIR . '/notify.stamp');

reset_files();
enable_mfa(true);                          // enabled, files vanilla: not protected
aegis_mfa_notify_patch_state();
$log = @file($NLOG) ?: [];
t('notify alert fired once', count($log) === 1 && strpos($log[0], '-i alert') !== false);
t('notify stamp written',    is_file(AEGIS_MFA_STATE_DIR . '/notify.stamp'));
aegis_mfa_notify_patch_state();            // next cron tick, same incident
t('notify de-duped', count(@file($NLOG) ?: []) === 1);

$res = aegis_mfa_install();                // fix it
t('notify precondition patched', ($res['ok'] ?? false) === true);
aegis_mfa_notify_patch_state();
$log = @file($NLOG) ?: [];
t('notify all-clear fired',  count($log) === 2 && strpos($log[1], 'restored') !== false);
t('notify stamp cleared',    !is_file(AEGIS_MFA_STATE_DIR . '/notify.stamp'));
aegis_mfa_notify_patch_state();
t('notify quiet when healthy', count(@file($NLOG) ?: []) === 2);

aegis_mfa_uninstall();                     // a fresh incident alerts again
aegis_mfa_notify_patch_state();
t('notify re-alerts new incident', count(@file($NLOG) ?: []) === 3);

enable_mfa(false);                         // admin turns it off while broken
aegis_mfa_notify_patch_state();
t('notify silent on disable',        count(@file($NLOG) ?: []) === 3);
t('notify stamp cleared on disable', !is_file(AEGIS_MFA_STATE_DIR . '/notify.stamp'));

// PREFLIGHT (read-only readiness report)
reset_files();
enable_mfa(false);
$pfa = md5_file($AUTH); $pfl = md5_file($LOGIN);
$pf = aegis_mfa_preflight();
t('preflight passes on vanilla', ($pf['ok'] ?? false) === true);
t('preflight live untouched', md5_file($AUTH) === $pfa && md5_file($LOGIN) === $pfl);
$names = array_column($pf['checks'], 'name');
t('preflight ran both rehearsals', count(preg_grep('/^rehearsal:/', $names)) === 2);
t('preflight left no temp litter', glob(sys_get_temp_dir() . '/aegis-mfa-preflight-*') === []);

// a restructured target: structure fails, overall fails, live untouched
file_put_contents($AUTH, str_replace('session_write_close();', 'session_wc();', file_get_contents($AUTH)));
$pfa = md5_file($AUTH);
$pf = aegis_mfa_preflight();
t('preflight fails on broken anchor', ($pf['ok'] ?? true) === false);
$badnames = [];
foreach ($pf['checks'] as $c) { if (!$c['ok']) $badnames[] = $c['name'] . '=' . $c['detail']; }
t('preflight names the reason', strpos(implode(',', $badnames), 'anchor_missing') !== false);
t('preflight broken file untouched', md5_file($AUTH) === $pfa);
reset_files();

// on an already-patched system it reports fine and skips the rehearsal
enable_mfa(true);
aegis_mfa_install();
$pf = aegis_mfa_preflight();
t('preflight ok when patched', ($pf['ok'] ?? false) === true);
t('preflight skips rehearsal when patched',
    count(preg_grep('/^rehearsal:/', array_column($pf['checks'], 'name'))) === 0);
aegis_mfa_uninstall();
enable_mfa(false);

// a leftover kill switch is flagged
file_put_contents(dirname(AEGIS_MFA_COMPAT_FILE) . '/DISABLE.flag', '1');
$pf = aegis_mfa_preflight();
t('preflight flags stale DISABLE.flag', ($pf['ok'] ?? true) === false);
@unlink(dirname(AEGIS_MFA_COMPAT_FILE) . '/DISABLE.flag');

// PLUGIN UPGRADE: a stale hook must be refreshed, not left running
reset_files();
enable_mfa(true);
aegis_mfa_install();
$specs = aegis_mfa_patch_specs();
t('fresh patch is current', aegis_mfa_hook_current($specs['auth']) && aegis_mfa_hook_current($specs['login']));

// simulate what a plugin upgrade leaves behind: our markers are still in
// the login file, but the hook body between them is the OLD version's.
$body = file_get_contents($AUTH);
$stale = preg_replace(
    '/(AEGIS_MFA_HOOK_BEGIN).*?(\/\/ AEGIS_MFA_HOOK_END)/s',
    "$1\n    \$x = 1;  // hook from an older release\n    $2",
    $body, 1);
file_put_contents($AUTH, $stale);
t('stale hook still has markers', aegis_mfa_is_patched($AUTH));
t('stale hook detected',          !aegis_mfa_hook_current($specs['auth']));
t('stale hook: other file fine',  aegis_mfa_hook_current($specs['login']));

// the next reconcile (what the PLG install, the boot hook and the cron all
// call) must strip the old hook and lay down the shipped one
$res = aegis_mfa_reconcile_patches();
t('upgrade reconcile ok',      ($res['ok'] ?? false) === true);
t('stale hook refreshed',      aegis_mfa_hook_current($specs['auth']));
t('refreshed file lints',      aegis_mfa_php_lint($AUTH));
t('old hook body gone',        strpos(file_get_contents($AUTH), 'older release') === false);
t('refresh kept one hook',     substr_count(file_get_contents($AUTH), 'AEGIS_MFA_HOOK_BEGIN') === 1);
t('refresh left backup',       is_file($AUTH . '.aegis-bak'));
t('refresh no temp litter',    !is_file($AUTH . '.aegis-tmp'));

// and the refreshed file must still unpatch to byte-identical vanilla
aegis_mfa_uninstall();
t('refreshed file restores clean', file_get_contents($AUTH) === file_get_contents("$FX/auth-request.vanilla.php"));
enable_mfa(false);
reset_files();
reset_files();
@unlink(AEGIS_MFA_COMPAT_FILE);
@unlink(AEGIS_MFA_COMPAT_DEFAULT);

// no shipped baseline: clean no-op
$m = aegis_mfa_merge_compat();
t('merge no-op without baseline', ($m['ok'] ?? false) === true && ($m['added'] ?? ['x']) === []);
t('merge no-op wrote nothing', !is_file(AEGIS_MFA_COMPAT_FILE));

// shipped baseline, empty flash: both versions land
file_put_contents(AEGIS_MFA_COMPAT_DEFAULT, json_encode(['versions' => [
    '7.3.2' => ['auth' => 'sha-a-732', 'login' => 'sha-l-732'],
    '7.4.0' => ['auth' => 'sha-a-740', 'login' => 'sha-l-740'],
]]));
$m = aegis_mfa_merge_compat();
t('merge adds missing versions', ($m['added'] ?? []) === ['7.3.2', '7.4.0']);
$shas = aegis_mfa_compat_shas();
t('merged shas readable', isset($shas['sha-a-732'], $shas['sha-l-740']));

// idempotent: nothing new the second time
$m = aegis_mfa_merge_compat();
t('merge idempotent', ($m['added'] ?? ['x']) === []);

// flash wins: a locally captured entry is never overwritten
aegis_mfa_update_json(AEGIS_MFA_COMPAT_FILE, function ($d) {
    $d['versions']['7.3.2'] = ['auth' => 'local-a', 'login' => 'local-l'];
    return $d;
}, 0644);
$m = aegis_mfa_merge_compat();
t('merge respects flash owner', ($m['added'] ?? ['x']) === []);
$compat = aegis_mfa_read_json(AEGIS_MFA_COMPAT_FILE);
t('local capture preserved', $compat['versions']['7.3.2']['auth'] === 'local-a');
@unlink(AEGIS_MFA_COMPAT_DEFAULT);

echo "\ninstall.test.php: {$pass} passed, {$fail} failed\n";
// cleanup
exec('rm -rf ' . escapeshellarg($work));
exit($fail === 0 ? 0 : 1);
