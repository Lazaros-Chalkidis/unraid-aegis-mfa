<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaHelpers.php';

function aegis_mfa_emhttp(): string {
    return defined('AEGIS_MFA_EMHTTP') ? AEGIS_MFA_EMHTTP : '/usr/local/emhttp';
}

function aegis_mfa_gate_path(): string {
    return defined('AEGIS_MFA_GATE_PATH')
        ? AEGIS_MFA_GATE_PATH
        : '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaGate.php';
}

// one spec per Unraid file: a unique vanilla anchor plus a marker-bounded fail-open hook, all patch or none
function aegis_mfa_patch_specs(): array {
    $gate = aegis_mfa_gate_path();

    $authAnchor =
        "    session_write_close();\n" .
        "    http_response_code(200);\n" .
        "    exit;";
    $authHook =
        "    // AEGIS_MFA_HOOK_BEGIN\n" .
        "    \$aegis_gate = '$gate';\n" .
        "    if (is_file(\$aegis_gate)) {\n" .
        "      try {\n" .
        "        require_once \$aegis_gate;\n" .
        "        if (function_exists('aegis_mfa_passed') && aegis_mfa_passed() === false) {\n" .
        "          session_write_close();\n" .
        "          http_response_code(401);\n" .
        "          exit;\n" .
        "        }\n" .
        "      } catch (\\Throwable \$e) { /* fail-open */ }\n" .
        "    }\n" .
        "    // AEGIS_MFA_HOOK_END";

    $loginAnchor = "    if (\$_SESSION && !empty(\$_SESSION['unraid_user'])) {";
    $loginHook =
        "        // AEGIS_MFA_HOOK_BEGIN\n" .
        "        \$aegis_gate = '$gate';\n" .
        "        if (is_file(\$aegis_gate)) {\n" .
        "            try {\n" .
        "                require_once \$aegis_gate;\n" .
        "                if (function_exists('aegis_mfa_passed') && aegis_mfa_passed() === false) {\n" .
        "                    include dirname(\$aegis_gate, 2) . '/challenge.view.php';\n" .
        "                    exit;\n" .
        "                }\n" .
        "            } catch (\\Throwable \$e) { /* fail-open */ }\n" .
        "        }\n" .
        "        // AEGIS_MFA_HOOK_END";

    return [
        'auth' => [
            'path'   => aegis_mfa_emhttp() . '/auth-request.php',
            'anchor' => $authAnchor,
            'hook'   => $authHook,
            'position' => 'before',

            'require' => ['$_SESSION["unraid_login"]', 'session_start()', 'http_response_code'],

            'forbid'  => ['AEGIS_MFA_HOOK'],
        ],
        'login' => [
            'path'   => aegis_mfa_emhttp() . '/webGui/include/.login.php',
            'anchor' => $loginAnchor,
            'hook'   => $loginHook,
            'position' => 'after',
            'require' => ["\$_SESSION['unraid_user']", 'session_start()', '$start_page'],
            'forbid'  => ['AEGIS_MFA_HOOK'],
        ],
    ];
}

function aegis_mfa_file_sha(string $path): ?string {
    if (!is_file($path)) return null;
    $h = @hash_file('sha256', $path);
    return $h === false ? null : $h;
}

function aegis_mfa_is_patched(string $path): bool {
    if (!is_file($path)) return false;
    $c = @file_get_contents($path);
    return $c !== false
        && strpos($c, 'AEGIS_MFA_HOOK_BEGIN') !== false
        && strpos($c, 'AEGIS_MFA_HOOK_END') !== false;
}

function aegis_mfa_hook_in_file(string $path): ?string {
    $c = @file_get_contents($path);
    if ($c === false) return null;
    $a = strpos($c, 'AEGIS_MFA_HOOK_BEGIN');
    $b = strpos($c, 'AEGIS_MFA_HOOK_END');
    if ($a === false || $b === false || $b < $a) return null;
    return substr($c, $a, $b - $a);
}

// compare the hook body, not just the markers: an upgrade replaces our code but not the login files, so a stale hook would run forever
function aegis_mfa_hook_current(array $spec): bool {
    $have = aegis_mfa_hook_in_file($spec['path']);
    if ($have === null) return false;
    $a = strpos($spec['hook'], 'AEGIS_MFA_HOOK_BEGIN');
    $b = strpos($spec['hook'], 'AEGIS_MFA_HOOK_END');
    if ($a === false || $b === false) return false;
    return $have === substr($spec['hook'], $a, $b - $a);
}

// PHP_BINARY under the webGUI is php-fpm and cannot lint, so resolve a real CLI binary once
function aegis_mfa_php_cli(): string {
    static $bin = null;
    if ($bin !== null) return $bin;
    if (defined('AEGIS_MFA_PHP_BIN')) return $bin = AEGIS_MFA_PHP_BIN;
    if (PHP_SAPI === 'cli' && PHP_BINARY !== '') return $bin = PHP_BINARY;
    foreach (['/usr/bin/php', '/usr/local/bin/php'] as $p) {
        if (@is_executable($p)) return $bin = $p;
    }
    if (PHP_BINARY !== '' && strpos(basename(PHP_BINARY), 'fpm') === false) {
        return $bin = PHP_BINARY;
    }
    return $bin = 'php';
}

function aegis_mfa_php_lint(string $path): bool {
    $out = []; $code = 1;
    @exec(escapeshellarg(aegis_mfa_php_cli()) . ' -l ' . escapeshellarg($path) . ' 2>/dev/null', $out, $code);
    return $code === 0;
}

function aegis_mfa_may_patch(string $path): bool {
    if (aegis_mfa_is_patched($path)) return true;
    $spec = null;
    foreach (aegis_mfa_patch_specs() as $s) {
        if ($s['path'] === $path) { $spec = $s; break; }
    }
    if ($spec === null) return false;
    return aegis_mfa_structure_ok($spec) === '';
}

// patch on shape, not on shipped hashes: survives cosmetic point releases, refuses when the structure really changes
function aegis_mfa_structure_ok(array $spec): string {
    $path = $spec['path'];
    if (!is_file($path)) return 'missing';
    $c = @file_get_contents($path);
    if ($c === false) return 'unreadable';

    foreach (($spec['forbid'] ?? []) as $bad) {
        if (strpos($c, $bad) !== false) return 'already_patched';
    }

    foreach (($spec['require'] ?? []) as $sig) {
        if (strpos($c, $sig) === false) return 'signature_missing';
    }

    $n = substr_count($c, $spec['anchor']);
    if ($n === 0) return 'anchor_missing';
    if ($n > 1)  return 'anchor_ambiguous';

    if (!aegis_mfa_php_lint($path)) return 'invalid_php';

    return '';
}

// the patched copy is built and linted on the side, the live file is only swapped once it is known good
function aegis_mfa_patch_file(array $spec): bool {
    $path = $spec['path'];
    if (aegis_mfa_is_patched($path)) return true;
    if (!is_file($path)) return false;

    $orig = @file_get_contents($path);
    if ($orig === false) return false;

    $count = substr_count($orig, $spec['anchor']);
    if ($count !== 1) return false;

    $position = $spec['position'] ?? 'before';
    if ($position === 'after') {
        $replacement = $spec['anchor'] . "\n" . $spec['hook'];
    } else {
        $replacement = $spec['hook'] . "\n" . $spec['anchor'];
    }
    $patched = str_replace($spec['anchor'], $replacement, $orig);

    $tmp = $path . '.aegis-tmp';
    if (@file_put_contents($tmp, $patched) === false) { @unlink($tmp); return false; }
    @chmod($tmp, fileperms($path) & 07777);
    @chown($tmp, fileowner($path));
    @chgrp($tmp, filegroup($path));

    if (!aegis_mfa_php_lint($tmp)) {
        @unlink($tmp);
        @error_log("aegis-mfa: patched copy of $path failed php -l, original untouched");
        return false;
    }

    $bak = $path . '.aegis-bak';
    if (@file_put_contents($bak, $orig) === false) { @unlink($tmp); return false; }
    if (!@rename($tmp, $path)) { @unlink($tmp); @unlink($bak); return false; }
    return true;
}

function aegis_mfa_unpatch_file(array $spec): bool {
    $path = $spec['path'];
    if (!is_file($path)) return true;
    if (!aegis_mfa_is_patched($path)) { @unlink($path . '.aegis-bak'); return true; }

    $c = @file_get_contents($path);
    if ($c === false) return false;

    $trailing = '/[ \t]*\/\/ AEGIS_MFA_HOOK_BEGIN.*?\/\/ AEGIS_MFA_HOOK_END\n/s';
    $leading  = '/\n[ \t]*\/\/ AEGIS_MFA_HOOK_BEGIN.*?\/\/ AEGIS_MFA_HOOK_END/s';
    $clean = preg_replace($trailing, '', $c, 1, $did);
    if (!$did) {
        $clean = preg_replace($leading, '', $c, 1, $did);
    }
    if ($clean === null || !$did || $clean === $c) return false;

    $tmp = $path . '.aegis-tmp';
    if (@file_put_contents($tmp, $clean) === false) { @unlink($tmp); return false; }
    @chmod($tmp, fileperms($path) & 07777);
    @chown($tmp, fileowner($path));
    @chgrp($tmp, filegroup($path));

    if (!aegis_mfa_php_lint($tmp)) {
        @unlink($tmp);
        @error_log("aegis-mfa: unpatch of $path failed php -l, left patched");
        return false;
    }
    if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
    @unlink($path . '.aegis-bak');
    return true;
}

function aegis_mfa_install(): array {
    $specs = aegis_mfa_patch_specs();

    foreach ($specs as $spec) {
        if (aegis_mfa_is_patched($spec['path']) && !aegis_mfa_hook_current($spec)) {
            @error_log('aegis-mfa: stale hook in ' . $spec['path'] . ', refreshing');
            aegis_mfa_unpatch_file($spec);
        }
    }

    foreach ($specs as $k => $spec) {
        if (aegis_mfa_is_patched($spec['path'])) continue;
        $why = aegis_mfa_structure_ok($spec);
        if ($why !== '') {

            aegis_mfa_uninstall();
            return ['ok' => false, 'reason' => "$why:$k", 'state' => 'unpatched'];
        }
    }

    foreach ($specs as $k => $spec) {
        if (!aegis_mfa_patch_file($spec)) {
            aegis_mfa_uninstall();
            return ['ok' => false, 'reason' => "patch_failed:$k", 'state' => 'unpatched'];
        }
    }
    return ['ok' => true, 'reason' => 'patched', 'state' => 'patched'];
}

function aegis_mfa_uninstall(): array {
    $ok = true;
    foreach (aegis_mfa_patch_specs() as $spec) {
        if (!aegis_mfa_unpatch_file($spec)) $ok = false;
    }
    return ['ok' => $ok, 'state' => $ok ? 'unpatched' : 'partial'];
}

// brings the patches in line with the saved setting, run from the boot hook and the cron
function aegis_mfa_reconcile_patches(): array {
    if (!aegis_mfa_enabled()) {
        return aegis_mfa_uninstall() + ['action' => 'disabled'];
    }
    $res = aegis_mfa_install();
    $res['action'] = 'enabled';
    return $res;
}

function aegis_mfa_patch_state(): array {
    $patched = 0; $total = 0;
    foreach (aegis_mfa_patch_specs() as $spec) {
        $total++;
        if (aegis_mfa_is_patched($spec['path'])) $patched++;
    }
    $state = ($patched === 0) ? 'none' : (($patched === $total) ? 'full' : 'partial');
    return ['patched' => $patched, 'total' => $total, 'state' => $state];
}

function aegis_mfa_notify_patch_state(): void {
    try {
        $notify = defined('AEGIS_MFA_NOTIFY_BIN')
            ? AEGIS_MFA_NOTIFY_BIN
            : '/usr/local/emhttp/webGui/scripts/notify';
        if (!@is_executable($notify)) return;
        $stamp   = aegis_mfa_state() . '/notify.stamp';
        $enabled = aegis_mfa_enabled();
        $full    = aegis_mfa_patch_state()['state'] === 'full';

        if ($enabled && !$full) {
            if (is_file($stamp)) return;
            @mkdir(dirname($stamp), 0700, true);
            @file_put_contents($stamp, (string)time());
            @exec(escapeshellarg($notify)
                . ' -e ' . escapeshellarg('Aegis MFA')
                . ' -s ' . escapeshellarg('Aegis MFA is not protecting logins')
                . ' -d ' . escapeshellarg('MFA is enabled but the login patches are not active, so password-only login is in effect (fail-open). This usually follows an Unraid update that restructured the login files. Check Settings > Aegis MFA and the syslog for aegis-mfa entries.')
                . ' -i ' . escapeshellarg('alert') . ' >/dev/null 2>&1');
            return;
        }
        if (is_file($stamp)) {
            @unlink($stamp);
            if ($enabled && $full) {
                @exec(escapeshellarg($notify)
                    . ' -e ' . escapeshellarg('Aegis MFA')
                    . ' -s ' . escapeshellarg('Aegis MFA protection restored')
                    . ' -d ' . escapeshellarg('The login patches are active again and 2FA is enforced as configured.')
                    . ' -i ' . escapeshellarg('normal') . ' >/dev/null 2>&1');
            }

        }
    } catch (\Throwable $e) {
        @error_log('aegis-mfa notify: ' . $e->getMessage());
    }
}

function aegis_mfa_preflight(): array {
    $checks = [];
    $add = function (string $name, bool $ok, string $detail = '') use (&$checks) {
        $checks[] = ['name' => $name, 'ok' => $ok, 'detail' => $detail];
    };

    $probe = tempnam(sys_get_temp_dir(), 'amfa-lint');
    @file_put_contents($probe, "<?php\n");
    $add('php_lint_works', aegis_mfa_php_lint($probe), aegis_mfa_php_cli());
    @unlink($probe);

    $ver = '';
    if (is_readable('/etc/unraid-version')) {
        $raw = (string)@file_get_contents('/etc/unraid-version');
        if (preg_match('/^version="([^"]+)"/m', $raw, $m)) $ver = $m[1];
    }
    if ($ver === '') {
        $add('unraid_version', true, 'unreadable (fine on a test box)');
    } else {
        $add('unraid_version', version_compare($ver, '7.3.1', '>='), $ver);
    }

    $vanilla = [];
    foreach (aegis_mfa_patch_specs() as $spec) {
        $base = basename($spec['path']);
        if (aegis_mfa_is_patched($spec['path'])) {
            $add("structure:$base", true, 'already patched (rehearsal skipped)');
            continue;
        }
        $r = aegis_mfa_structure_ok($spec);
        $add("structure:$base", $r === '', $r === '' ? 'vanilla, anchor ok' : $r);
        if ($r === '') $vanilla[] = $spec;
    }

    $liveBefore = [];
    foreach (aegis_mfa_patch_specs() as $spec) {
        $liveBefore[$spec['path']] = @md5_file($spec['path']);
    }
    // exclusive create: a pre-existing name here could be a symlink pointing at a live file
    $tmp = sys_get_temp_dir() . '/aegis-mfa-preflight-' . getmypid() . '-' . bin2hex(random_bytes(6));
    if (!@mkdir($tmp, 0700, true) || !is_dir($tmp) || is_link($tmp)) {
        $add('rehearsal', false, 'could not create a private temp dir');
        $vanilla = [];
    }
    foreach ($vanilla as $spec) {
        $base = basename($spec['path']);
        $copy = $tmp . '/' . $base;
        $step = '';
        if (!@copy($spec['path'], $copy)) $step = 'copy';
        $c = $spec; $c['path'] = $copy;
        if ($step === '' && !aegis_mfa_patch_file($c))    $step = 'patch';
        if ($step === '' && !aegis_mfa_is_patched($copy)) $step = 'marker';
        if ($step === '' && !aegis_mfa_unpatch_file($c))  $step = 'unpatch';
        if ($step === '' && md5_file($copy) !== $liveBefore[$spec['path']]) $step = 'restore_diff';
        $add("rehearsal:$base", $step === '',
            $step === '' ? 'patch, lint, unpatch, byte-identical' : "failed at: $step");
    }
    foreach (array_diff(@scandir($tmp) ?: [], ['.', '..']) as $f) @unlink($tmp . '/' . $f);
    @rmdir($tmp);
    $untouched = true;
    foreach ($liveBefore as $p => $sum) {
        if (@md5_file($p) !== $sum) $untouched = false;
    }
    $add('live_untouched', $untouched, 'live files identical before and after');

    $flash = aegis_mfa_flash();
    $p = $flash . '/.preflight-probe';
    $w = @file_put_contents($p, '1') !== false; @unlink($p);
    $add('flash_writable', $w, $flash);
    $state = aegis_mfa_state();
    @mkdir($state, 0700, true);
    $p = $state . '/.preflight-probe';
    $w = @file_put_contents($p, '1') !== false; @unlink($p);
    $add('state_writable', $w, $state);

    $flag = $flash . '/DISABLE.flag';
    $add('disable_flag_absent', !is_file($flag), $flag);

    $notify = defined('AEGIS_MFA_NOTIFY_BIN')
        ? AEGIS_MFA_NOTIFY_BIN
        : '/usr/local/emhttp/webGui/scripts/notify';
    $add('notify_script', true,
        @is_executable($notify) ? 'found' : 'missing (alerts disabled, fine on a test box)');

    $ok = true;
    foreach ($checks as $c) { if (!$c['ok']) { $ok = false; break; } }
    return ['ok' => $ok, 'checks' => $checks];
}

