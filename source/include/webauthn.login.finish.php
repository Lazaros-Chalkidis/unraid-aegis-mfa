<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

// finishes a WebAuthn login ceremony - all the real work lives in aegis_mfa_verify_passkey_assertion(), this file is just wiring

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaEnroll.php';

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

function amfa_webauthn_fail(int $status, string $reason): void {
    http_response_code($status);
    echo json_encode(['ok' => false, 'reason' => $reason]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') amfa_webauthn_fail(405, 'method_not_allowed');

aegis_mfa_session_ensure();
$user = aegis_mfa_current_user();
if ($user === '') amfa_webauthn_fail(401, 'no_session');

$body = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($body) || !aegis_mfa_csrf_check((string)($body['csrf'] ?? ''))) amfa_webauthn_fail(403, 'csrf');

$cred = $body['credential'] ?? null;
if (!is_array($cred)) amfa_webauthn_fail(400, 'malformed');

$res = aegis_mfa_verify_passkey_assertion($user, $cred);
if (($res['ok'] ?? false) === true) {
    echo json_encode(['ok' => true, 'redirect' => '/']);
    exit;
}
echo json_encode($res);
