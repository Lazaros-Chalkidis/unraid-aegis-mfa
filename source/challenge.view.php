<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaEnroll.php';

// reached through the 401 redirect, so a background request lands here too
if (!aegis_mfa_request_wants_page()) {
    http_response_code(401);
    exit;
}

$amfaUser  = aegis_mfa_current_user();
$amfaError = '';
$amfaLockSeconds = 0;

$amfaStart = isset($start_page) && is_string($start_page) ? $start_page : 'Dashboard';
$amfaStart = preg_replace('#^[/\\\\]+#', '', $amfaStart);  // runs inside .login.php scope, session already open and $start_page set

$amfaStatus = aegis_mfa_user_status($amfaUser);
$amfaDry    = !aegis_mfa_enforcing();

$amfaGrace = 0;
if ($amfaStatus === 'pending') {
    $amfaSec   = aegis_mfa_read_json(aegis_mfa_flash() . '/secrets.json');
    $amfaGrace = (int)($amfaSec['users'][$amfaUser]['grace_until'] ?? 0);
}

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
                <?php if ($amfaDry): ?>
                <p class="amfa-skip"><a href="/login?aegis_mfa_skip=1">Continue without a code (dry-run)</a></p>
                <?php endif; ?>
            </div>
            <div class="amfa-shieldbox"><?= aegis_mfa_shell_shield() ?></div>
        </div>
        <p class="amfa-hint">You can also enter one of your backup codes (xxxxx-xxxxx).</p>
<?php
}

aegis_mfa_mark_seen($amfaUser);

$amfaLockedTip = 'Option 1: From a terminal on your PC run <code>ssh root@ip</code> or hostname '
    . '(e.g. <code>ssh root@tower</code> or <code>ssh root@10.0.0.5</code>), give your root password, '
    . 'then run <code>aegis-mfa disable</code>. A keyboard and monitor on the server does the same. '
    . 'If <code>aegis-mfa</code> is missing or errors out, run<br>'
    . '<code>bash /boot/config/plugins/aegis.mfa/recover.sh</code><br>'
    . 'Option 2: With physical access, shut the server down, take the USB boot drive out and put it '
    . 'in any computer. In <code>config/plugins/aegis.mfa/</code> on the stick create an empty file '
    . 'named <code>DISABLE.flag</code>, put it back and boot. This does not work with an internal '
    . 'boot device, so there use Option 1.';

aegis_mfa_shell_close('<a href="/logout">Sign out</a>'
    . '<span class="amfa-lockout" tabindex="0">Locked Out?'
    . '<span class="amfa-lockout-tip" role="tooltip">' . $amfaLockedTip . '</span></span>');
