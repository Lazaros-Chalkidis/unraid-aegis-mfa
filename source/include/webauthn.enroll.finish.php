<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

// finishes a WebAuthn registration ceremony, routed by session state, never by anything the client claims
// in-progress wizard enrolment goes to aegis_mfa_verify_enrollment_passkey, an already-verified session adding a passkey goes to aegis_mfa_add_passkey

require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaEnroll.php';
require_once '/usr/local/emhttp/plugins/aegis.mfa/include/AegisMfaAdmin.php';

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
if (!aegis_mfa_webauthn_available()) amfa_webauthn_fail(409, 'webauthn_unavailable');

$body = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($body) || !aegis_mfa_csrf_check((string)($body['csrf'] ?? ''))) amfa_webauthn_fail(403, 'csrf');

$cred = $body['credential'] ?? null;
if (!is_array($cred)) amfa_webauthn_fail(400, 'malformed');

$origin = aegis_mfa_webauthn_rp_origin();
$state = aegis_mfa_enroll_state();

if ($state !== null && ($state['method'] ?? '') === 'passkey' && ($state['user'] ?? '') === $user) {
    echo json_encode(aegis_mfa_verify_enrollment_passkey($cred, $origin));
    exit;
}

if (aegis_mfa_session_verified()) {
    $label = is_string($body['label'] ?? null) && trim((string)$body['label']) !== '' ? (string)$body['label'] : 'Passkey';
    echo json_encode(aegis_mfa_add_passkey($user, $cred, $origin, $label));
    exit;
}

amfa_webauthn_fail(403, 'not_allowed');
