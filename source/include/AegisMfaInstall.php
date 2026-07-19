<?php
/*
 * Aegis MFA for Unraid - installer / patcher
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Patches two Unraid core files to wire in the 2FA gate. Every safety
 * rail here exists to guarantee ONE thing: a bad patch can never lock a
 * user out. Failure always resolves to "MFA off, files vanilla".
 *
 * Guarantees:
 *  - never patch a file we don't recognise (sha256 vs known-good vanilla)
 *  - never keep a patch that fails `php -l` (auto-rollback from backup)
 *  - never leave the system half-patched (all files or none)
 *  - re-applied idempotently from the boot hook and cron
 */

require_once __DIR__ . '/AegisMfaHelpers.php';

// docroot base, injectable for tests
function aegis_mfa_emhttp(): string {
    return defined('AEGIS_MFA_EMHTTP') ? AEGIS_MFA_EMHTTP : '/usr/local/emhttp';
}

// absolute path to the plugin's gate, embedded in the patches
function aegis_mfa_gate_path(): string {
    return defined('AEGIS_MFA_GATE_PATH')
        ? AEGIS_MFA_GATE_PATH
        : '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaGate.php';
}

// each spec targets one Unraid file: find a unique vanilla anchor, insert a marker-bounded fail-open hook next to it
function aegis_mfa_patch_specs(): array {
    $gate = aegis_mfa_gate_path();

    // auth-request.php: gate after the password, hook goes before the success exit
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

        // .login.php: a password-only user gets bounced start page -> gate -> login, the challenge cuts into that loop.
    // The redirect line exists twice in this file, the already-logged-in test once, so the hook goes inside that block
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
            'position' => 'before',               // hook goes before the anchor line
            // all of these must be present or we refuse to touch the file
            'require' => ['$_SESSION["unraid_login"]', 'session_start()', 'http_response_code'],
            // and none of these may be present (someone else patched it)
            'forbid'  => ['AEGIS_MFA_HOOK'],
        ],
        'login' => [
            'path'   => aegis_mfa_emhttp() . '/webGui/include/.login.php',
            'anchor' => $loginAnchor,
            'hook'   => $loginHook,
            'position' => 'after',                // hook goes after the anchor line (inside the if)
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

// the hook text currently between the markers, or null
function aegis_mfa_hook_in_file(string $path): ?string {
    $c = @file_get_contents($path);
    if ($c === false) return null;
    $a = strpos($c, 'AEGIS_MFA_HOOK_BEGIN');
    $b = strpos($c, 'AEGIS_MFA_HOOK_END');
    if ($a === false || $b === false || $b < $a) return null;
    return substr($c, $a, $b - $a);
}

// is the hook in the file the one this build ships?
// an upgrade replaces our code but not the login files, so compare the body, not just the markers, or a stale hook runs forever
function aegis_mfa_hook_current(array $spec): bool {
    $have = aegis_mfa_hook_in_file($spec['path']);
    if ($have === null) return false;
    $a = strpos($spec['hook'], 'AEGIS_MFA_HOOK_BEGIN');
    $b = strpos($spec['hook'], 'AEGIS_MFA_HOOK_END');
    if ($a === false || $b === false) return false;
    return $have === substr($spec['hook'], $a, $b - $a);
}

// PHP_BINARY under the webGUI is php-fpm, which cannot lint, so resolve a real CLI binary once and cache it
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

// known-good vanilla sha256s from compat.json, informational only, the real gate is structural
function aegis_mfa_compat_shas(): array {
    $file = defined('AEGIS_MFA_COMPAT_FILE')
        ? AEGIS_MFA_COMPAT_FILE
        : aegis_mfa_flash() . '/compat.json';
    $data = aegis_mfa_read_json($file);
    $shas = [];
    foreach (($data['versions'] ?? []) as $ver => $files) {
        if (!is_array($files)) continue;
        foreach ($files as $sha) if (is_string($sha)) $shas[$sha] = true;
    }
    return $shas;
}

// both targets byte-identical to a tested release? drives the soft untested notice, never blocks
function aegis_mfa_version_validated(): bool {
    $known = aegis_mfa_compat_shas();
    if (!$known) return false;
    foreach (aegis_mfa_patch_specs() as $spec) {
        if (aegis_mfa_is_patched($spec['path'])) continue;   // can't compare, assume ok
        $sha = aegis_mfa_file_sha($spec['path']);
        if ($sha === null || !isset($known[$sha])) return false;
    }
    return true;
}

// the real gate: patch on SHAPE, not on shipped hashes. anchor exactly once, every require marker present, no forbid marker.
// Survives cosmetic point releases, refuses the moment the structure actually changes
function aegis_mfa_may_patch(string $path): bool {
    if (aegis_mfa_is_patched($path)) return true;
    $spec = null;
    foreach (aegis_mfa_patch_specs() as $s) {
        if ($s['path'] === $path) { $spec = $s; break; }
    }
    if ($spec === null) return false;
    return aegis_mfa_structure_ok($spec) === '';
}

// '' when the file is safe to patch, otherwise a short reason code
function aegis_mfa_structure_ok(array $spec): string {
    $path = $spec['path'];
    if (!is_file($path)) return 'missing';
    $c = @file_get_contents($path);
    if ($c === false) return 'unreadable';

    // must not already carry a hook, ours or anyone's
    foreach (($spec['forbid'] ?? []) as $bad) {
        if (strpos($c, $bad) !== false) return 'already_patched';
    }
    // must look like the file we think it is
    foreach (($spec['require'] ?? []) as $sig) {
        if (strpos($c, $sig) === false) return 'signature_missing';
    }
    // the insertion point must be unique
    $n = substr_count($c, $spec['anchor']);
    if ($n === 0) return 'anchor_missing';
    if ($n > 1)  return 'anchor_ambiguous';

    // and currently valid php, so a rollback target is sane
    if (!aegis_mfa_php_lint($path)) return 'invalid_php';

    return '';
}

// apply one spec. on any failure the live file is untouched: the patched copy is built and linted on the side
function aegis_mfa_patch_file(array $spec): bool {
    $path = $spec['path'];
    if (aegis_mfa_is_patched($path)) return true;      // idempotent
    if (!is_file($path)) return false;

    $orig = @file_get_contents($path);
    if ($orig === false) return false;

    // anchor must appear exactly once or we refuse
    $count = substr_count($orig, $spec['anchor']);
    if ($count !== 1) return false;

    // each position adds exactly one newline around the block and unpatch removes exactly that, so removal is byte-identical
    $position = $spec['position'] ?? 'before';
    if ($position === 'after') {
        $replacement = $spec['anchor'] . "\n" . $spec['hook'];
    } else {
        $replacement = $spec['hook'] . "\n" . $spec['anchor'];
    }
    $patched = str_replace($spec['anchor'], $replacement, $orig);

    // atomic swap: this IS the live login path, so lint a side copy and rename() it in, the file is never half-written
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

    // backup first, then swap: after a successful patch the backup always exists
    $bak = $path . '.aegis-bak';
    if (@file_put_contents($bak, $orig) === false) { @unlink($tmp); return false; }
    if (!@rename($tmp, $path)) { @unlink($tmp); @unlink($bak); return false; }
    return true;
}

// surgically remove our block from whatever the current content is, no reliance on the backup
function aegis_mfa_unpatch_file(array $spec): bool {
    $path = $spec['path'];
    if (!is_file($path)) return true;                  // nothing to do
    if (!aegis_mfa_is_patched($path)) { @unlink($path . '.aegis-bak'); return true; }

    $c = @file_get_contents($path);
    if ($c === false) return false;

    // two removal shapes matching the two insert positions, try the trailing-newline form first
    $trailing = '/[ \t]*\/\/ AEGIS_MFA_HOOK_BEGIN.*?\/\/ AEGIS_MFA_HOOK_END\n/s';
    $leading  = '/\n[ \t]*\/\/ AEGIS_MFA_HOOK_BEGIN.*?\/\/ AEGIS_MFA_HOOK_END/s';
    $clean = preg_replace($trailing, '', $c, 1, $did);
    if (!$did) {
        $clean = preg_replace($leading, '', $c, 1, $did);
    }
    if ($clean === null || !$did || $clean === $c) return false;

    // same atomic pattern as patch_file
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

// bring the system to fully patched, or on any failure roll ALL patches out. never half-wired, always fail-open
function aegis_mfa_install(): array {
    $specs = aegis_mfa_patch_specs();

    // strip any hook that is not the one this build ships, so an upgraded plugin re-patches with current code
    foreach ($specs as $spec) {
        if (aegis_mfa_is_patched($spec['path']) && !aegis_mfa_hook_current($spec)) {
            @error_log('aegis-mfa: stale hook in ' . $spec['path'] . ', refreshing');
            aegis_mfa_unpatch_file($spec);
        }
    }

    // capture before patching, a hooked file no longer matches any vanilla sha
    $validated = aegis_mfa_version_validated();

    // is every file structurally safe to touch
    foreach ($specs as $k => $spec) {
        if (aegis_mfa_is_patched($spec['path'])) continue;           // already done
        $why = aegis_mfa_structure_ok($spec);
        if ($why !== '') {
            // Unraid restructured the file or something else patched it. refuse, stay vanilla, MFA off
            aegis_mfa_uninstall();
            return ['ok' => false, 'reason' => "$why:$k", 'state' => 'unpatched'];
        }
    }

    // apply all, first failure rolls everything back
    foreach ($specs as $k => $spec) {
        if (!aegis_mfa_patch_file($spec)) {
            aegis_mfa_uninstall();
            return ['ok' => false, 'reason' => "patch_failed:$k", 'state' => 'unpatched'];
        }
    }
    return ['ok' => true, 'reason' => 'patched', 'state' => 'patched',
            'validated' => $validated];
}

// remove every patch, idempotent. uninstall and the rollback path
function aegis_mfa_uninstall(): array {
    $ok = true;
    foreach (aegis_mfa_patch_specs() as $spec) {
        if (!aegis_mfa_unpatch_file($spec)) $ok = false;
    }
    return ['ok' => $ok, 'state' => $ok ? 'unpatched' : 'partial'];
}

// boot and cron entry point: enabled means fully patched or fully unpatched, disabled means unpatched
function aegis_mfa_reconcile_patches(): array {
    if (!aegis_mfa_enabled()) {
        return aegis_mfa_uninstall() + ['action' => 'disabled'];
    }
    $res = aegis_mfa_install();
    $res['action'] = 'enabled';
    return $res;
}

// how many files currently carry the hook
function aegis_mfa_patch_state(): array {
    $patched = 0; $total = 0;
    foreach (aegis_mfa_patch_specs() as $spec) {
        $total++;
        if (aegis_mfa_is_patched($spec['path'])) $patched++;
    }
    $state = ($patched === 0) ? 'none' : (($patched === $total) ? 'full' : 'partial');
    return ['patched' => $patched, 'total' => $total, 'state' => $state];
}

// alert when MFA is enabled but the patches are not in place, fail-open means logins quietly drop to password-only.
// One alert per incident: a RAM stamp de-dups the cron, a reboot resets it, recovery sends a short all-clear
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
            if (is_file($stamp)) return;                   // already alerted
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
        // the admin turned it off themselves, nothing to say
        }
    } catch (\Throwable $e) {
        @error_log('aegis-mfa notify: ' . $e->getMessage());
    }
}

// seed compat.json from a clean system during QA, refuses files already patched
function aegis_mfa_capture_compat(string $version): array {
    $out = [];
    foreach (aegis_mfa_patch_specs() as $k => $spec) {
        if (aegis_mfa_is_patched($spec['path'])) return ['ok' => false, 'reason' => "patched:$k"];
        $sha = aegis_mfa_file_sha($spec['path']);
        if ($sha === null) return ['ok' => false, 'reason' => "missing:$k"];
        $out[$k] = $sha;
    }
    $file = defined('AEGIS_MFA_COMPAT_FILE') ? AEGIS_MFA_COMPAT_FILE : aegis_mfa_flash() . '/compat.json';
    $ok = aegis_mfa_update_json($file, function ($d) use ($version, $out) {
        if (!isset($d['versions']) || !is_array($d['versions'])) $d['versions'] = [];
        $d['versions'][$version] = $out;
        return $d;
    }, 0644);
    return ['ok' => $ok, 'version' => $version, 'shas' => $out];
}

// pre-enable readiness report, read-only: patching is rehearsed on temp copies
function aegis_mfa_preflight(): array {
    $checks = [];
    $add = function (string $name, bool $ok, string $detail = '') use (&$checks) {
        $checks[] = ['name' => $name, 'ok' => $ok, 'detail' => $detail];
    };

    // the lint binary must actually lint, proven on a scratch file
    $probe = tempnam(sys_get_temp_dir(), 'amfa-lint');
    @file_put_contents($probe, "<?php\n");
    $add('php_lint_works', aegis_mfa_php_lint($probe), aegis_mfa_php_cli());
    @unlink($probe);

    // version gate, informational here, the PLG enforces it hard
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

    // structure of each live target, without touching it
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

    // full patch, lint, unpatch rehearsal on copies
    $liveBefore = [];
    foreach (aegis_mfa_patch_specs() as $spec) {
        $liveBefore[$spec['path']] = @md5_file($spec['path']);
    }
    $tmp = sys_get_temp_dir() . '/aegis-mfa-preflight-' . getmypid();
    @mkdir($tmp, 0700, true);
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

    // storage the runtime needs
    $flash = aegis_mfa_flash();
    $p = $flash . '/.preflight-probe';
    $w = @file_put_contents($p, '1') !== false; @unlink($p);
    $add('flash_writable', $w, $flash);
    $state = aegis_mfa_state();
    @mkdir($state, 0700, true);
    $p = $state . '/.preflight-probe';
    $w = @file_put_contents($p, '1') !== false; @unlink($p);
    $add('state_writable', $w, $state);

    // leftovers that would surprise: a forgotten kill switch
    $flag = $flash . '/DISABLE.flag';
    $add('disable_flag_absent', !is_file($flag), $flag);

    // without the notify script alerts silently no-op
    $notify = defined('AEGIS_MFA_NOTIFY_BIN')
        ? AEGIS_MFA_NOTIFY_BIN
        : '/usr/local/emhttp/webGui/scripts/notify';
    $add('notify_script', true,
        @is_executable($notify) ? 'found' : 'missing (alerts disabled, fine on a test box)');

    $ok = true;
    foreach ($checks as $c) { if (!$c['ok']) { $ok = false; break; } }
    return ['ok' => $ok, 'checks' => $checks];
}

// fold the shipped baseline into the flash compat.json, the flash copy owns its own captures
function aegis_mfa_merge_compat(): array {
    $pkg = defined('AEGIS_MFA_COMPAT_DEFAULT')
        ? AEGIS_MFA_COMPAT_DEFAULT
        : aegis_mfa_emhttp() . '/plugins/aegis.mfa/compat.default.json';
    $data = aegis_mfa_read_json($pkg);
    $add = [];
    foreach (($data['versions'] ?? []) as $ver => $files) {
        if (is_string($ver) && is_array($files)) $add[$ver] = $files;
    }
    if (!$add) return ['ok' => true, 'added' => []];

    $file = defined('AEGIS_MFA_COMPAT_FILE')
        ? AEGIS_MFA_COMPAT_FILE
        : aegis_mfa_flash() . '/compat.json';
    $added = [];
    $ok = aegis_mfa_update_json($file, function ($d) use ($add, &$added) {
        if (!isset($d['versions']) || !is_array($d['versions'])) $d['versions'] = [];
        foreach ($add as $ver => $files) {
            if (!isset($d['versions'][$ver])) {
                $d['versions'][$ver] = $files;
                $added[] = $ver;
            }
        }
        return $d;
    }, 0644);
    return ['ok' => $ok, 'added' => $ok ? $added : []];
}
