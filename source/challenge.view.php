<?php
/*
 * Aegis MFA for Unraid - 2FA challenge page
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Included from the patched .login.php when a logged-in user still needs
 * 2FA. Renders the code prompt and handles its own POST. On success the
 * session is marked verified and we redirect to the start page; the gate
 * then returns 200 everywhere.
 *
 * Runs inside .login.php scope: session already started, $start_page set.
 */

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaEnroll.php';

$amfaUser  = aegis_mfa_current_user();
$amfaError = '';
$amfaLockSeconds = 0;
// leading slashes stripped: Location //host is protocol-relative, an open redirect. costs nothing
$amfaStart = isset($start_page) && is_string($start_page) ? $start_page : 'Dashboard';
$amfaStart = preg_replace('#^[/\\\\]+#', '', $amfaStart);

// user status decides which screen this really is
$amfaStatus = aegis_mfa_user_status($amfaUser);
$amfaDry    = !aegis_mfa_enforcing();

// grace deadline, shown on the pending screen
$amfaGrace = 0;
if ($amfaStatus === 'pending') {
    $amfaSec   = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $amfaGrace = (int)($amfaSec['users'][$amfaUser]['grace_until'] ?? 0);
}

// explicit skip, legitimate only while the prompt is optional (grace running or dry-run). sets the once-per-session
// flag and never grants 2FA, which is why a GET is acceptable. everyone else falls through to their prompt
if (isset($_GET['aegis_mfa_skip']) && ($amfaDry || $amfaStatus === 'pending')) {
    aegis_mfa_mark_nudged($amfaUser);
    header('Location: /' . $amfaStart);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['aegis_mfa_code'])) {
    if (!aegis_mfa_csrf_check($_POST['aegis_mfa_csrf'] ?? '')) {
        $amfaError = 'Session expired, please try again.';
    } else {
        $res = aegis_mfa_verify_submission($amfaUser, (string)$_POST['aegis_mfa_code']);
        if (($res['ok'] ?? false) === true) {
            header('Location: /' . $amfaStart);
            exit;
        }
        if (($res['locked'] ?? false) === true) {
            $amfaLockSeconds = (int)($res['retry_after'] ?? 0);
            $amfaError = 'Too many attempts. Try again in ' . max(1, (int)ceil($amfaLockSeconds / 60)) . ' min.';
        } else {
            $amfaError = 'Invalid code, ' . (int)($res['remaining'] ?? 0) . ' attempts remaining.';
        }
    }
}

$amfaCsrf   = aegis_mfa_csrf_token();
$amfaTime   = date('H:i:s T');
$amfaEsc    = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaShell.php';

aegis_mfa_shell_open('Two-factor authentication');

if ($amfaStatus === 'pending' || $amfaStatus === 'locked') {
?>
        <div class="amfa-cols">
            <div class="amfa-main">
                <p class="amfa-lead">Set up two-factor authentication</p>
                <p class="amfa-sub">
                    <?php if ($amfaStatus === 'locked'): ?>
                    Your enrolment grace period has expired. You must set up 2FA now to continue.
                    <?php else: ?>
                    Your administrator requires two-factor authentication for this account.
                    <?php if ($amfaGrace > 0): ?>
                    You can put this off until <?= $amfaEsc(date('Y-m-d', $amfaGrace)) ?>.
                    <?php endif; ?>
                    <?php endif; ?>
                </p>
                <form method="get" action="/plugins/aegis.mfa/include/setup.php">
                    <button type="submit" class="amfa-btn">Begin setup</button>
                </form>
                <?php if ($amfaStatus === 'pending' || $amfaDry): ?>
                <p class="amfa-skip"><a href="/login?aegis_mfa_skip=1"><?=
                    $amfaStatus === 'pending' ? 'Not now, continue to the dashboard' : 'Continue anyway (dry-run)'
                ?></a></p>
                <?php endif; ?>
            </div>
            <div class="amfa-shieldbox"><?= aegis_mfa_shell_shield() ?></div>
        </div>
<?php
} else {
?>
        <div class="amfa-cols">
            <div class="amfa-main">
                <p class="amfa-sub">Enter the 6-digit code from your authenticator app</p>
                <form method="post" autocomplete="off">
                    <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
                    <input class="amfa-code" type="text" name="aegis_mfa_code" inputmode="numeric"
                           autocomplete="one-time-code" maxlength="11" placeholder="000000"
                           autofocus <?= $amfaLockSeconds > 0 ? 'disabled' : '' ?>>
                    <button type="submit" class="amfa-btn" <?= $amfaLockSeconds > 0 ? 'disabled' : '' ?>>Verify</button>
                </form>
                <?php if ($amfaError !== ''): ?>
                <p class="amfa-error">
                    <?= $amfaEsc($amfaError) ?>
                    <span class="amfa-clock">Server time: <?= $amfaEsc($amfaTime) ?></span>
                </p>
                <?php endif; ?>
                <p class="amfa-hint">You can also enter one of your backup codes (xxxxx-xxxxx).</p>
                <?php if ($amfaDry): ?>
                <p class="amfa-skip"><a href="/login?aegis_mfa_skip=1">Continue without a code (dry-run)</a></p>
                <?php endif; ?>
            </div>
            <div class="amfa-shieldbox"><?= aegis_mfa_shell_shield() ?></div>
        </div>
<?php
}

// the Recovery section's fail-open exits, readable right where a locked-out admin stands
$amfaLockedTip = 'From SSH or the local console run <code>aegis-mfa disable</code>. '
    . 'With physical access, create the file <code>/boot/config/plugins/aegis.mfa/DISABLE.flag</code> '
    . 'on the flash drive and reboot. If even the CLI will not run (for example after an Unraid '
    . 'PHP upgrade), run <code>bash /boot/config/plugins/aegis.mfa/recover.sh</code>, a pure-bash '
    . 'script that restores the stock login files with no PHP at all. All three fully disable MFA, '
    . 'and none of them touches your password login.';

aegis_mfa_shell_close('<a href="/logout">Sign out</a>'
    . '<span class="amfa-lockout" tabindex="0">Locked Out?'
    . '<span class="amfa-lockout-tip" role="tooltip">' . $amfaLockedTip . '</span></span>'
    . '<span class="amfa-user">Signed in as ' . $amfaEsc($amfaUser) . '</span>');
