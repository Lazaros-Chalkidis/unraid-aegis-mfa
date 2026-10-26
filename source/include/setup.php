<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaEnroll.php';
require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaQr.php';

aegis_mfa_session_ensure();

$amfaEsc = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');

$amfaUser = aegis_mfa_current_user();

// a password login is required in every path, and an enrolled user also needs a bypass token or 2FA this session
if ($amfaUser !== '' && isset($_GET['user'], $_GET['token']) && (string)$_GET['user'] === $amfaUser) {
    if (aegis_mfa_consume_bypass_token($amfaUser, (string)$_GET['token'])) {
        $_SESSION['aegis_mfa_token_ok'] = ['user' => $amfaUser, 'until' => time() + 3600];

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

$amfaStatus = aegis_mfa_user_status($amfaUser);
if (!aegis_mfa_setup_access_ok($amfaUser)) {

    @syslog(LOG_WARNING, 'aegis-mfa: setup wizard refused for enrolled user '
        . $amfaUser . ' from ' . aegis_mfa_client_ip());
    header('Location: /');
    exit;
}

$amfaStep  = 1;
$amfaError = '';
$amfaCsrf  = aegis_mfa_csrf_token();

$amfaUnraidCsrf = (string)(aegis_mfa_var_ini()['csrf_token'] ?? '');
$amfaServer = aegis_mfa_server_name();

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

// passkeys as a method only exist when the admin configured an origin and this request is served from it (aegis_mfa_webauthn_available() - a UX gate, not the security boundary)
// unconfigured, every path below behaves exactly as it did before passkeys existed: straight into the TOTP wizard
$amfaWebauthnAvailable = aegis_mfa_webauthn_available();

if ($amfaAction === 'choose_totp' || $amfaAction === 'choose_passkey') {
    $amfaMethodChosen = ($amfaAction === 'choose_passkey' && $amfaWebauthnAvailable) ? 'passkey' : 'totp';
    $amfaEnroll = aegis_mfa_begin_enrollment($amfaUser, 'Aegis MFA', $amfaServer, $amfaMethodChosen);
    $amfaStep = 1;
} elseif ($amfaAction === '' || $amfaAction === 'restart' || aegis_mfa_enroll_state() === null) {
    if (!in_array($amfaAction, ['verify', 'confirm', 'back', 'back_to_method', 'passkey_created'], true)) {
        if ($amfaWebauthnAvailable) {
            aegis_mfa_cancel_enrollment();
            $amfaStep = 0; // method chooser
        } else {
            $amfaEnroll = aegis_mfa_begin_enrollment($amfaUser, 'Aegis MFA', $amfaServer, 'totp');
            $amfaStep = 1;
        }
    }
}

if ($amfaAction === 'to_verify') {
    $amfaStep = 2;
}

if ($amfaAction === 'back') {
    $amfaStep = 1;
}

if ($amfaAction === 'back_to_method' && $amfaWebauthnAvailable) {
    aegis_mfa_cancel_enrollment();
    $amfaStep = 0;
}

if ($amfaAction === 'verify') {
    if (aegis_mfa_verify_enrollment_totp((string)($_POST['code'] ?? ''))) {
        $amfaStep = 3;
    } else {
        $amfaStep = 2;
        $amfaError = 'That code did not match. Check the app and try again.';
    }
}

// the passkey ceremony already ran and was verified against webauthn.enroll.finish.php - this just advances the wizard once session state shows it succeeded
if ($amfaAction === 'passkey_created') {
    $amfaPkState = aegis_mfa_enroll_state();
    if ($amfaPkState !== null && ($amfaPkState['method'] ?? '') === 'passkey' && !empty($amfaPkState['passkey_ok'])) {
        $amfaStep = 3;
    } else {
        $amfaStep = 1;
        $amfaError = 'Passkey creation did not complete. Try again.';
    }
}

if ($amfaAction === 'confirm') {
    $res = aegis_mfa_commit_enrollment((string)($_POST['backup_confirm'] ?? ''));
    if (($res['ok'] ?? false) === true) {

        unset($_SESSION['aegis_mfa_token_ok']);
        header('Location: /');
        exit;
    }
    $reason = $res['reason'] ?? '';
    if ($reason === 'totp_not_verified' || $reason === 'passkey_not_verified') {
        $amfaConfirmState = aegis_mfa_enroll_state();
        $amfaStep = ($amfaConfirmState !== null && ($amfaConfirmState['method'] ?? '') === 'passkey') ? 1 : 2;
        $amfaError = $reason === 'passkey_not_verified'
            ? 'Create a passkey first.'
            : 'Verify a code from the app first.';
    } else {
        $amfaStep = 3;
        $amfaError = $reason === 'bad_backup_confirm'
            ? 'That backup code does not match. Copy one exactly as shown above.'
            : 'Could not save the enrolment. Please try again.';
    }
}

$amfaState = aegis_mfa_enroll_state();
if ($amfaState === null && $amfaStep !== 0) {
    if ($amfaWebauthnAvailable) {
        $amfaStep = 0;
    } else {
        $amfaEnroll = aegis_mfa_begin_enrollment($amfaUser, 'Aegis MFA', $amfaServer, 'totp');
        $amfaState  = aegis_mfa_enroll_state();
        $amfaStep   = 1;
    }
}

$amfaMethod = $amfaState['method'] ?? 'totp';
$amfaSecret = ''; $amfaCodes = []; $amfaUri = ''; $amfaQrSvg = ''; $amfaSecretGrouped = '';
if ($amfaStep !== 0 && $amfaState !== null) {
    $amfaCodes = $amfaState['backup_plain'];
    if ($amfaMethod === 'totp') {
        $amfaSecret = $amfaState['secret'];
        $amfaUri    = aegis_totp_uri($amfaSecret, $amfaUser . '@' . $amfaServer, 'Aegis MFA');
        $amfaQrSvg  = aegis_qr_svg(aegis_qr_encode($amfaUri), 5, 4);
        $amfaSecretGrouped = trim(chunk_split($amfaSecret, 4, ' '));
    }
}

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
<?php if ($amfaStep === 0): ?>
        <?php if ($amfaError !== ''): ?>
        <p class="amfa-error" style="margin: 0 0 1.6rem;"><?= $amfaEsc($amfaError) ?></p>
        <?php endif; ?>
        <div class="amfa-cols">
            <div class="amfa-main" style="max-width: none;">
                <p class="amfa-lead">Choose how you'll sign in</p>
                <p class="amfa-sub">You can add the other method later from Settings.</p>
                <div class="amfa-row" style="justify-content: flex-start; gap: 1.2rem;">
                    <form method="post">
                        <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
                        <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
                        <button class="amfa-btn" type="submit" name="aegis_action" value="choose_totp">Authenticator app</button>
                    </form>
                    <form method="post">
                        <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
                        <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
                        <button class="amfa-btn" type="submit" name="aegis_action" value="choose_passkey">Passkey</button>
                    </form>
                </div>
            </div>
        </div>
        <form method="post" class="amfa-row" style="margin-top: 1.6rem;">
            <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
            <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
            <button class="amfa-btn ghost" type="submit" name="aegis_action" value="cancel">Cancel</button>
        </form>
<?php else: ?>
        <div class="amfa-steps">
<?php if ($amfaMethod === 'passkey'): ?>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 1 ? 'on' : '' ?>">1</div><span class="<?= $amfaStep === 1 ? 'on' : '' ?>">Create passkey</span></div>
            <div class="amfa-bar"></div>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 3 ? 'on' : '' ?>">2</div><span class="<?= $amfaStep === 3 ? 'on' : '' ?>">Backup codes</span></div>
<?php else: ?>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 1 ? 'on' : '' ?>">1</div><span class="<?= $amfaStep === 1 ? 'on' : '' ?>">Scan</span></div>
            <div class="amfa-bar"></div>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 2 ? 'on' : '' ?>">2</div><span class="<?= $amfaStep === 2 ? 'on' : '' ?>">Verify</span></div>
            <div class="amfa-bar"></div>
            <div class="amfa-step"><div class="amfa-dot <?= $amfaStep >= 3 ? 'on' : '' ?>">3</div><span class="<?= $amfaStep === 3 ? 'on' : '' ?>">Backup codes</span></div>
<?php endif; ?>
        </div>

        <?php if ($amfaError !== ''): ?>
        <p class="amfa-error" style="margin: 0 0 1.6rem;"><?= $amfaEsc($amfaError) ?></p>
        <?php endif; ?>

<?php if ($amfaStep === 1 && $amfaMethod === 'passkey'): ?>
        <div class="amfa-cols">
            <div class="amfa-main" style="max-width: none;">
                <p class="amfa-lead">Create a passkey</p>
                <p class="amfa-sub">Your browser will ask for your fingerprint, face, screen lock PIN, or a
                    security key. Only the resulting public key is ever sent to this server.</p>
                <p class="amfa-error" id="amfaSetupPkErr" style="display:none;"></p>
                <button type="button" class="amfa-btn" id="amfaSetupPkBtn">Create passkey</button>
            </div>
        </div>
        <form method="post" id="amfaPkAdvanceForm" style="display:none;">
            <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
            <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
            <input type="hidden" name="aegis_action" value="passkey_created">
        </form>
        <form method="post" class="amfa-row">
            <input type="hidden" name="aegis_mfa_csrf" value="<?= $amfaEsc($amfaCsrf) ?>">
            <input type="hidden" name="csrf_token" value="<?= $amfaEsc($amfaUnraidCsrf) ?>">
            <button class="amfa-btn ghost" type="submit" name="aegis_action" value="back_to_method">Back</button>
            <button class="amfa-btn ghost" type="submit" name="aegis_action" value="cancel">Cancel</button>
        </form>
<script>
<?= aegis_mfa_webauthn_js() ?>
(function () {
    var btn = document.getElementById('amfaSetupPkBtn');
    var err = document.getElementById('amfaSetupPkErr');
    var form = document.getElementById('amfaPkAdvanceForm');
    if (!btn) return;
    if (!amfaWebauthnSupported()) {
        err.textContent = 'This browser does not support passkeys. Use "Back" and choose an authenticator app instead.';
        err.style.display = 'block';
        btn.disabled = true;
        return;
    }
    btn.addEventListener('click', function () {
        err.style.display = 'none';
        btn.disabled = true;
        btn.textContent = 'Waiting for your passkey...';
        amfaWebauthnRegister('<?= $amfaEsc($amfaCsrf) ?>', '<?= $amfaEsc($amfaUnraidCsrf) ?>', 'Passkey', function () {
            form.submit();
        }, function (reason) {
            btn.disabled = false;
            btn.textContent = 'Create passkey';
            err.textContent = 'Passkey creation did not complete (' + reason + '). Try again.';
            err.style.display = 'block';
        });
    });
})();
</script>

<?php elseif ($amfaStep === 1): ?>
        <div class="amfa-cols">
            <?php if ($amfaQrSvg !== ''): ?>
            <div class="amfa-qrbox"><div class="amfa-qr"><?= $amfaQrSvg ?></div></div>
            <?php endif; ?>
            <div class="amfa-main" style="max-width: none;">
              <?php if ($amfaQrSvg !== ''): ?>
                <p class="amfa-lead">Scan with your authenticator app</p>
                <p class="amfa-sub">Use Google Authenticator, Authy, 1Password, or any TOTP-compatible app.</p>
                <p class="amfa-label">Or enter this secret manually</p>
              <?php else: ?>
                <p class="amfa-lead">Enter this secret in your authenticator app</p>
                <p class="amfa-sub">The QR code could not be drawn for this account name, so type the
                   secret instead. Google Authenticator, Authy, 1Password and any other TOTP app take it.</p>
              <?php endif; ?>
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
<?php endif; // amfaStep === 0 ?>
<?php
aegis_mfa_shell_close();
