<?php
/*
 * Aegis MFA for Unraid - enrolment wizard (setup.php)
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Three steps: 1 scan QR, 2 verify a code, 3 save backup codes and confirm
 * one of them. Enrolment is committed only at the end of step 3.
 *
 * Access rules (a password login is required in ALL cases):
 *  - 'pending', 'locked' and 'none' users may enrol themselves. The gate
 *    lets the wizard URL through (see aegis_mfa_request_is_setup) and the
 *    challenge screen offers "Begin setup".
 *  - an 'enrolled' user may RE-enrol only with a one-time bypass token
 *    (?user=X&token=Y, the lost-authenticator path) or after passing 2FA
 *    in this session. A password alone is never enough to replace an
 *    existing secret; that would make the second factor pointless.
 */

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaEnroll.php';
require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaQr.php';

aegis_mfa_session_ensure();

$amfaEsc = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');

// access always requires a password login. a bypass token does not skip it, it un-expires a locked grace window
$amfaUser = aegis_mfa_current_user();
$amfaViaToken = false;

if ($amfaUser !== '' && isset($_GET['user'], $_GET['token']) && (string)$_GET['user'] === $amfaUser) {
    if (aegis_mfa_consume_bypass_token($amfaUser, (string)$_GET['token'])) {
        $amfaViaToken = true;
        // the token is single-use but the wizard spans several POSTs, so acceptance is held in session for an hour
        $_SESSION['aegis_mfa_token_ok'] = ['user' => $amfaUser, 'until' => time() + 3600];
        // re-open the grace window so locked clears for this enrolment
        aegis_mfa_update_json(aegis_mfa_flash() . '/secrets.json',
            function ($sec) use ($amfaUser) {
                if (isset($sec['users'][$amfaUser])) {
                    $sec['users'][$amfaUser]['grace_until'] = time() + 3600;
                }
                return $sec;
            });
    }
}
if ($amfaUser === '') {
    header('Location: /login');
    exit;
}

// an enrolled user re-enrolling with only the password would be a full 2FA bypass,
// so that path needs a bypass token or a 2FA-verified session
$amfaTok = $_SESSION['aegis_mfa_token_ok'] ?? null;
$amfaTokenOk = $amfaViaToken
    || (is_array($amfaTok)
        && ($amfaTok['user'] ?? '') === $amfaUser
        && (int)($amfaTok['until'] ?? 0) > time());
$amfaStatus = aegis_mfa_user_status($amfaUser);
if (!in_array($amfaStatus, ['pending', 'locked', 'none'], true)
    && !$amfaTokenOk
    && !aegis_mfa_session_verified()) {
    // an enrolled user probing the wizard with only a password is what a stolen credential looks like, leave a trace
    @syslog(LOG_WARNING, 'aegis-mfa: setup wizard refused for enrolled user '
        . $amfaUser . ' from ' . aegis_mfa_client_ip());
    header('Location: /');
    exit;
}

$amfaStep  = 1;
$amfaError = '';
$amfaCsrf  = aegis_mfa_csrf_token();
// Unraid's local_prepend.php kills any POST without the webGUI csrf_token from var.ini before we even run.
// Ours rides in aegis_mfa_csrf, theirs in csrf_token, the prepend consumes theirs, the two never meet
$amfaVar = @parse_ini_file('/usr/local/emhttp/state/var.ini') ?: [];
$amfaUnraidCsrf = (string)($amfaVar['csrf_token'] ?? '');
$amfaHost  = strtok($_SERVER['HTTP_HOST'] ?? 'unraid', ':');

$amfaAction = $_POST['aegis_action'] ?? '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !aegis_mfa_csrf_check($_POST['aegis_mfa_csrf'] ?? '')) {
    $amfaAction = '';
    $amfaError  = 'Session expired, please start again.';
}

if ($amfaAction === 'cancel') {
    aegis_mfa_cancel_enrollment();
    unset($_SESSION['aegis_mfa_token_ok']);
    header('Location: /login');
    exit;
}

// begin or restart on first load or explicit restart
if ($amfaAction === '' || $amfaAction === 'restart' || aegis_mfa_enroll_state() === null) {
    if ($amfaAction !== 'verify' && $amfaAction !== 'confirm' && $amfaAction !== 'back') {
        $amfaEnroll = aegis_mfa_begin_enrollment($amfaUser, 'Aegis MFA', $amfaHost);
        $amfaStep = 1;
    }
}

if ($amfaAction === 'to_verify') {
    $amfaStep = 2;
}

// step 2 -> step 1 without touching the pending secret, the scanned QR stays valid. only restart regenerates
if ($amfaAction === 'back') {
    $amfaStep = 1;
}

if ($amfaAction === 'verify') {
    if (aegis_mfa_verify_enrollment_totp((string)($_POST['code'] ?? ''))) {
        $amfaStep = 3;
    } else {
        $amfaStep = 2;
        $amfaError = 'That code did not match. Check the app and try again.';
    }
}

if ($amfaAction === 'confirm') {
    $res = aegis_mfa_commit_enrollment((string)($_POST['backup_confirm'] ?? ''));
    if (($res['ok'] ?? false) === true) {
        // back through the gate: now enrolled they see the challenge once, or pass straight through on a trusted LAN
        unset($_SESSION['aegis_mfa_token_ok']);
        header('Location: /');
        exit;
    }
    $reason = $res['reason'] ?? '';
    if ($reason === 'totp_not_verified') {
        $amfaStep = 2;
        $amfaError = 'Verify a code from the app first.';
    } else {
        $amfaStep = 3;
        $amfaError = $reason === 'bad_backup_confirm'
            ? 'That backup code does not match. Copy one exactly as shown above.'
            : 'Could not save the enrolment. Please try again.';
    }
}

// state for rendering
$amfaState = aegis_mfa_enroll_state();
if ($amfaState === null) {   // safety: restart if session lost mid-wizard
    $amfaEnroll = aegis_mfa_begin_enrollment($amfaUser, 'Aegis MFA', $amfaHost);
    $amfaState  = aegis_mfa_enroll_state();
    $amfaStep   = 1;
}
$amfaSecret = $amfaState['secret'];
$amfaCodes  = $amfaState['backup_plain'];
$amfaUri    = aegis_totp_uri($amfaSecret, $amfaUser . '@' . $amfaHost, 'Aegis MFA');
$amfaQrSvg  = aegis_qr_svg(aegis_qr_encode($amfaUri), 5, 4);
$amfaSecretGrouped = trim(chunk_split($amfaSecret, 4, ' '));

$amfaWizCss = <<<'CSS'
.amfa-steps { display: flex; align-items: center; gap: .6rem; margin-bottom: 2rem; }
.amfa-step { display: flex; align-items: center; gap: .6rem; }
.amfa-dot {
    width: 2.2rem; height: 2.2rem; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem; font-weight: 700;
    border: 1px solid var(--amfa-mut); color: var(--amfa-mut);
}
.amfa-dot.on { border-color: var(--amfa-orange); color: var(--amfa-orange); }
.amfa-step span {
    font-size: 1.05rem; font-weight: 700; letter-spacing: .1rem;
    text-transform: uppercase; color: var(--amfa-mut);
}
.amfa-step span.on { color: var(--amfa-tx); }
.amfa-bar { width: 2rem; height: 1px; background: var(--amfa-mut); opacity: .4; }
.amfa-qrbox { flex-shrink: 0; }
.amfa-qr { width: 17rem; height: 17rem; background: #fff; border: 1px solid var(--amfa-in-bd); padding: .8rem; }
.amfa-qr svg { width: 100%; height: 100%; display: block; }
.amfa-secret {
    background: var(--amfa-in-bg); color: var(--amfa-in-tx);
    border: 1px solid var(--amfa-in-bd); padding: 1rem 1.2rem;
    font-family: "Courier New", monospace; font-size: 1.25rem; letter-spacing: .05em;
    user-select: all; word-break: break-all;
}
.amfa-label {
    font-size: 1.1rem; font-weight: 700; letter-spacing: .1rem;
    text-transform: uppercase; color: var(--amfa-mut); margin-bottom: .5rem;
}
.amfa-codes {
    display: grid; grid-template-columns: 1fr 1fr; gap: .5rem 1.4rem;
    background: var(--amfa-in-bg); color: var(--amfa-in-tx);
    border: 1px solid var(--amfa-in-bd); padding: 1.2rem 1.4rem;
    font-family: "Courier New", monospace; font-size: 1.3rem; margin-bottom: 1rem;
}
.amfa-dl {
    display: inline-block; color: var(--amfa-orange); font-size: 1.15rem;
    font-weight: 700; letter-spacing: .15rem; text-transform: uppercase;
    text-decoration: none; margin-bottom: 1.4rem;
}
.amfa-dl:hover { text-decoration: underline; }
.amfa-check {
    display: flex; gap: .8rem; align-items: flex-start;
    font-size: 1.2rem; color: var(--amfa-mut); margin: .4rem 0 1.2rem; line-height: 1.5;
}
.amfa-check input { margin-top: .3rem; }
.amfa-row .amfa-btn { padding: .9rem 1.6rem; }
CSS;

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaShell.php';

aegis_mfa_shell_open('Aegis MFA setup', $amfaWizCss);
?>
        <div class="amfa-steps">
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 1 ? 'on' : '' ?>">1</div><span class="<?= $amfaStep === 1 ? 'on' : '' ?>">Scan</span></div>
            <div class="amfa-bar"></div>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 2 ? 'on' : '' ?>">2</div><span class="<?= $amfaStep === 2 ? 'on' : '' ?>">Verify</span></div>
            <div class="amfa-bar"></div>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 3 ? 'on' : '' ?>">3</div><span class="<?= $amfaStep === 3 ? 'on' : '' ?>">Backup codes</span></div>
        </div>

        <?php if ($amfaError !== ''): ?>
        <p class="amfa-error" style="margin: 0 0 1.6rem;"><?= $amfaEsc($amfaError) ?></p>
        <?php endif; ?>

<?php if ($amfaStep === 1): ?>
        <div class="amfa-cols">
            <div class="amfa-qrbox"><div class="amfa-qr"><?= $amfaQrSvg ?></div></div>
            <div class="amfa-main" style="max-width: none;">
                <p class="amfa-lead">Scan with your authenticator app</p>
                <p class="amfa-sub">Use Google Authenticator, Authy, 1Password, or any TOTP-compatible app.</p>
                <p class="amfa-label">Or enter this secret manually</p>
                <div class="amfa-secret"><?= $amfaEsc($amfaSecretGrouped) ?></div>
            </div>
        </div>
        <form method="post" class="amfa-row">
            <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
            <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
            <button class="amfa-btn ghost" type="submit" name="aegis_action" value="cancel">Cancel</button>
            <button class="amfa-btn" type="submit" name="aegis_action" value="to_verify">I added the account</button>
        </form>

<?php elseif ($amfaStep === 2): ?>
        <div class="amfa-cols">
            <div class="amfa-main">
                <p class="amfa-lead">Enter the code from the app</p>
                <p class="amfa-sub">Confirms the account was added correctly before we continue.</p>
                <form method="post" autocomplete="off">
                    <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
                    <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
                    <input class="amfa-code" type="text" name="code" inputmode="numeric"
                           autocomplete="one-time-code" maxlength="7" placeholder="000000" autofocus>
                    <div class="amfa-row">
                        <button class="amfa-btn ghost" type="submit" name="aegis_action" value="back">Back</button>
                        <button class="amfa-btn" type="submit" name="aegis_action" value="verify">Verify</button>
                    </div>
                </form>
            </div>
            <div class="amfa-shieldbox"><?= aegis_mfa_shell_shield() ?></div>
        </div>

<?php else: ?>
        <div class="amfa-cols">
            <div class="amfa-main">
                <p class="amfa-lead">Save your backup codes</p>
                <p class="amfa-sub">Each code works once if you lose access to your authenticator.
                    Store them somewhere safe, they will not be shown again.</p>
                <div class="amfa-codes">
                    <?php foreach ($amfaCodes as $c): ?><div><?= $amfaEsc($c) ?></div><?php endforeach; ?>
                </div>
                <a class="amfa-dl" download="aegis-mfa-backup-codes-<?= $amfaEsc($amfaUser) ?>.txt"
                   href="data:text/plain;charset=utf-8,<?= rawurlencode("Aegis MFA backup codes for {$amfaUser}\n\n" . implode("\n", $amfaCodes) . "\n") ?>">
                   Download as text file</a>
                <form method="post" autocomplete="off">
                    <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
                    <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
                    <label class="amfa-check">
                        <input type="checkbox" required>
                        <span>I have saved these codes somewhere safe</span>
                    </label>
                    <p class="amfa-label">Type one of the codes above to confirm</p>
                    <input class="amfa-code" style="letter-spacing: .1em; font-size: 1.5rem;" type="text"
                           name="backup_confirm" maxlength="11" placeholder="xxxxx-xxxxx" autocomplete="off">
                    <div class="amfa-row">
                        <button class="amfa-btn ghost" type="submit" name="aegis_action" value="restart">Start over</button>
                        <button class="amfa-btn" type="submit" name="aegis_action" value="confirm">Finish setup</button>
                    </div>
                </form>
            </div>
            <div class="amfa-shieldbox"><?= aegis_mfa_shell_shield() ?></div>
        </div>
<?php endif; ?>
<?php
aegis_mfa_shell_close('<span></span><span class="amfa-user">Signed in as '
    . $amfaEsc($amfaUser) . '</span>');
