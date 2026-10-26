<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/AegisMfaHelpers.php';

function aegis_mfa_shell_theme(): string {
    return aegis_mfa_theme();
}

function aegis_mfa_shell_identity(): array {
    return [aegis_mfa_server_name(), trim((string)(aegis_mfa_var_ini()['COMMENT'] ?? ''))];
}

function aegis_mfa_shell_shield(int $size = 78): string {
    return '<svg width="' . $size . '" height="' . $size . '" viewBox="0 0 24 24" fill="none"'
         . ' stroke="currentColor" stroke-width="1.1" stroke-linecap="round"'
         . ' stroke-linejoin="round" aria-hidden="true">'
         . '<path d="M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6l7-3z"/>'
         . '<circle cx="12" cy="11" r="1.6"/>'
         . '<path d="M12 12.6V15.2"/></svg>';
}

// css and svg are inline: these pages render before authentication, when no asset is guaranteed to be served
function aegis_mfa_shell_open(string $title, string $extraCss = ''): void {
    $esc = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    [$host, $desc] = aegis_mfa_shell_identity();
    $theme = aegis_mfa_shell_theme();

    if (!headers_sent()) {
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Content-Security-Policy: frame-ancestors \'none\'');
    }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $esc($title) ?></title>
<style>
:root { font-size: 10px; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: clear-sans, "Helvetica Neue", Helvetica, Arial, sans-serif;
    background: var(--amfa-pg); color: var(--amfa-tx);
}
body.amfa-th-black {
    --amfa-pg: #1c1b1b; --amfa-card: #262626;
    --amfa-tx: #fff; --amfa-sub: #d4d4d4; --amfa-mut: #8f8f8f; --amfa-dim: #7d7d7d;
    --amfa-in-bg: #f2f2f2; --amfa-in-bd: #f2f2f2; --amfa-in-tx: #1c1b1b;
    --amfa-orange: #ff8d30; --amfa-shield: #dcdcdc;
    --amfa-shadow: 0 10px 40px rgba(0,0,0,.5);
}
body.amfa-th-gray {
    --amfa-pg: #121212; --amfa-card: #2c2c2c;
    --amfa-tx: #fff; --amfa-sub: #d4d4d4; --amfa-mut: #8f8f8f; --amfa-dim: #7d7d7d;
    --amfa-in-bg: #f2f2f2; --amfa-in-bd: #f2f2f2; --amfa-in-tx: #1c1b1b;
    --amfa-orange: #ff8d30; --amfa-shield: #dcdcdc;
    --amfa-shadow: 0 10px 40px rgba(0,0,0,.55);
}
body.amfa-th-white {
    --amfa-pg: #f2f2f2; --amfa-card: #fff;
    --amfa-tx: #1c1b1b; --amfa-sub: #4a4a4a; --amfa-mut: #757575; --amfa-dim: #8a8a8a;
    --amfa-in-bg: #f2f2f2; --amfa-in-bd: #cfcfcf; --amfa-in-tx: #1c1b1b;
    --amfa-orange: #e2621b; --amfa-shield: #9a9a9a;
    --amfa-shadow: 0 10px 30px rgba(0,0,0,.14);
}
body.amfa-th-azure {
    --amfa-pg: #e6eef6; --amfa-card: #fbfdff;
    --amfa-tx: #1c1b1b; --amfa-sub: #4a4a4a; --amfa-mut: #757575; --amfa-dim: #8a8a8a;
    --amfa-in-bg: #f2f2f2; --amfa-in-bd: #cfd7e0; --amfa-in-tx: #1c1b1b;
    --amfa-orange: #e2621b; --amfa-shield: #9aa6b2;
    --amfa-shadow: 0 10px 30px rgba(0,0,0,.14);
}
.amfa-card {
    width: 50rem; max-width: 100%;
    /* 9.6rem at our 10px root = the stock login's 6rem at its 16px root */
    margin: 9.6rem auto;
    background: var(--amfa-card); border-radius: 1rem;
    overflow: hidden; box-shadow: var(--amfa-shadow);
}
.amfa-banner {
    height: 11.8rem;
    background: linear-gradient(90deg, #e32929 0%, #ff8d30 100%);
    -webkit-clip-path: polygon(0 0, 100% 0, 100% 42%, 0 100%);
    clip-path: polygon(0 0, 100% 0, 100% 42%, 0 100%);
    padding: 2.6rem 3.2rem 0;
}
.amfa-banner span { color: #fff; font-size: 1.8rem; font-weight: 700; letter-spacing: .7rem; }
.amfa-body { padding: .6rem 3.4rem 3.4rem; }
h1 { font-size: 2.6rem; font-weight: 700; }
.amfa-desc { font-size: 1.2rem; font-weight: 700; color: var(--amfa-sub); margin: .2rem 0 2.4rem; }
.amfa-cols { display: flex; gap: 2.6rem; align-items: flex-start; }
.amfa-main { flex: 1; min-width: 0; max-width: 30rem; }
.amfa-shieldbox { flex-shrink: 0; padding-top: .6rem; color: var(--amfa-shield); }
.amfa-sub { font-size: 1.2rem; color: var(--amfa-mut); margin-bottom: 1rem; line-height: 1.55; }
.amfa-lead { font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; }
.amfa-code {
    width: 100%;
    background: var(--amfa-in-bg); color: var(--amfa-in-tx);
    border: 1px solid var(--amfa-in-bd); border-radius: 0;
    padding: 1.2rem 1.4rem;
    font-family: "Courier New", monospace; font-size: 1.7rem; letter-spacing: .4rem;
}
.amfa-code:focus { outline: none; border-color: var(--amfa-orange); }
.amfa-btn {
    display: inline-block; margin-top: 1.6rem;
    background: transparent;
    border: 1px solid var(--amfa-orange); color: var(--amfa-orange);
    font-size: 1.3rem; font-weight: 700; letter-spacing: .2rem; text-transform: uppercase;
    padding: .9rem 2.4rem; cursor: pointer;
}
.amfa-btn:hover:not(:disabled) {
    background: linear-gradient(90deg, #e32929, #ff8d30);
    border-color: transparent; color: #fff;
}
.amfa-btn:disabled { opacity: .45; cursor: not-allowed; }
.amfa-btn.ghost { border-color: var(--amfa-mut); color: var(--amfa-mut); }
.amfa-btn.ghost:hover { background: none; border-color: var(--amfa-sub); color: var(--amfa-sub); }
.amfa-row { display: flex; justify-content: space-between; gap: 1rem; }
.amfa-error { color: #e22828; font-size: 1.3rem; margin-top: 1.6rem; }
.amfa-error .amfa-clock { display: block; margin-top: .3rem; color: var(--amfa-mut); font-size: 1.1rem; }
.amfa-hint { font-size: 1.2rem; color: var(--amfa-mut); margin-top: 1.2rem; line-height: 1.55; }
.amfa-skip { margin-top: 1.8rem; }
.amfa-skip a {
    color: var(--amfa-mut); font-size: 1.15rem; font-weight: 700;
    letter-spacing: .15rem; text-transform: uppercase; text-decoration: none;
}
.amfa-skip a:hover { color: var(--amfa-orange); }
.amfa-foot { display: flex; justify-content: space-between; align-items: center; margin-top: 2.6rem; position: relative; }
.amfa-foot a {
    color: var(--amfa-orange); font-size: 1.2rem; font-weight: 700;
    letter-spacing: .2rem; text-transform: uppercase; text-decoration: none;
}
.amfa-foot a:hover { text-decoration: underline; }
.amfa-lockout {
    font-size: 1.2rem; color: var(--amfa-dim);
    border-bottom: 1px dashed var(--amfa-dim); cursor: help;
}
.amfa-lockout:hover, .amfa-lockout:focus {
    color: var(--amfa-orange); border-bottom-color: var(--amfa-orange); outline: none;
}
.amfa-lockout-tip {
    display: none; position: absolute; left: 0; right: 0;
    bottom: calc(100% + 1.1rem);
    background: var(--amfa-pg); border: 1px solid var(--amfa-orange);
    border-radius: .6rem; padding: 1.4rem 1.6rem;
    font-size: 1.15rem; line-height: 1.6; color: var(--amfa-sub);
    box-shadow: var(--amfa-shadow); z-index: 5;
    text-align: left; text-transform: none; letter-spacing: normal; font-weight: 400;
    cursor: auto;
}
.amfa-lockout:hover .amfa-lockout-tip, .amfa-lockout:focus .amfa-lockout-tip { display: block; }
.amfa-lockout-tip code { font-family: "Courier New", monospace; font-size: 1.1rem; color: var(--amfa-orange); }
@media (max-width: 560px) {
    .amfa-shieldbox { display: none; }
    .amfa-main { max-width: none; }
}
/* same breakpoint the stock login uses: card goes flush and full width */
@media (max-width: 500px) {
    body { background: var(--amfa-card); }
    .amfa-card { margin: 0; border-radius: 0; width: 100%; box-shadow: none; }
    .amfa-banner { border-radius: 0; }
}
<?= $extraCss ?>
</style>
</head>
<body class="amfa-th-<?= $esc($theme) ?>">
<div class="amfa-card">
    <div class="amfa-banner"><span>AEGIS MFA</span></div>
    <div class="amfa-body">
        <h1><?= $esc($host) ?></h1>
        <p class="amfa-desc"><?= $desc !== '' ? $esc($desc) : '&nbsp;' ?></p>
<?php
}

// shared WebAuthn JS for the two pre-auth pages (challenge.view.php, setup.php) - returned as a bare string, not a <script> tag
// both pages inline their own CSS/JS since no asset is guaranteed to be served before auth, so each caller wraps this in its own <script> block
function aegis_mfa_webauthn_js(): string {
    return <<<'JS'
function amfaB64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
}
function amfaBufToB64u(buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function amfaPrepCreateOptions(o) {
    o.challenge = amfaB64uToBuf(o.challenge);
    o.user.id = amfaB64uToBuf(o.user.id);
    if (o.excludeCredentials) o.excludeCredentials = o.excludeCredentials.map(function (c) {
        return { type: c.type, id: amfaB64uToBuf(c.id) };
    });
    return o;
}
function amfaPrepRequestOptions(o) {
    o.challenge = amfaB64uToBuf(o.challenge);
    if (o.allowCredentials) o.allowCredentials = o.allowCredentials.map(function (c) {
        return { type: c.type, id: amfaB64uToBuf(c.id) };
    });
    return o;
}
function amfaCredToJson(cred, isCreate) {
    var response = isCreate
        ? { clientDataJSON: amfaBufToB64u(cred.response.clientDataJSON),
            attestationObject: amfaBufToB64u(cred.response.attestationObject) }
        : { clientDataJSON: amfaBufToB64u(cred.response.clientDataJSON),
            authenticatorData: amfaBufToB64u(cred.response.authenticatorData),
            signature: amfaBufToB64u(cred.response.signature) };
    return { id: cred.id, type: cred.type, response: response };
}
function amfaWebauthnSupported() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
}
// unraidCsrf is Unraid's own native token (var.ini csrf_token), required by webGUI's auto_prepend_file regardless of our own aegis_mfa_csrf token
// sent as a header since our body is JSON, not a form field the native check would see in $_POST
function amfaWebauthnRegister(csrf, unraidCsrf, label, onOk, onErr) {
    fetch('/plugins/aegis.mfa/include/webauthn.enroll.begin.php', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Csrf-Token': unraidCsrf },
        body: JSON.stringify({ csrf: csrf })
    }).then(function (r) { return r.json(); }).then(function (begin) {
        if (!begin.ok) throw new Error(begin.reason || 'begin_failed');
        return navigator.credentials.create({ publicKey: amfaPrepCreateOptions(begin.options) });
    }).then(function (cred) {
        return fetch('/plugins/aegis.mfa/include/webauthn.enroll.finish.php', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Csrf-Token': unraidCsrf },
            body: JSON.stringify({ csrf: csrf, label: label, credential: amfaCredToJson(cred, true) })
        });
    }).then(function (r) { return r.json(); }).then(function (fin) {
        if (fin.ok) onOk(fin); else onErr(fin.reason || 'register_failed');
    }).catch(function (e) { onErr((e && e.message) || 'error'); });
}
function amfaWebauthnLogin(csrf, unraidCsrf, onOk, onErr) {
    fetch('/plugins/aegis.mfa/include/webauthn.login.begin.php', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Csrf-Token': unraidCsrf },
        body: JSON.stringify({ csrf: csrf })
    }).then(function (r) { return r.json(); }).then(function (begin) {
        if (!begin.ok) throw new Error(begin.reason || 'begin_failed');
        return navigator.credentials.get({ publicKey: amfaPrepRequestOptions(begin.options) });
    }).then(function (cred) {
        return fetch('/plugins/aegis.mfa/include/webauthn.login.finish.php', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Csrf-Token': unraidCsrf },
            body: JSON.stringify({ csrf: csrf, credential: amfaCredToJson(cred, false) })
        });
    }).then(function (r) { return r.json(); }).then(function (fin) {
        if (fin.ok) onOk(fin); else onErr(fin.reason || 'login_failed');
    }).catch(function (e) { onErr((e && e.message) || 'error'); });
}
JS;
}

function aegis_mfa_shell_close(string $footHtml = ''): void {
    if ($footHtml !== '') {
        echo '        <div class="amfa-foot">' . $footHtml . "</div>\n";
    }
    echo "    </div>\n</div>\n</body>\n</html>\n";
}
