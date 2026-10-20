<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

// begins a WebAuthn registration ceremony, called by both the wizard's passkey step and Settings "Add a passkey"

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
if (!aegis_mfa_setup_access_ok($user)) amfa_webauthn_fail(403, 'not_allowed');
if (!aegis_mfa_webauthn_available()) amfa_webauthn_fail(409, 'webauthn_unavailable');

$body = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($body) || !aegis_mfa_csrf_check((string)($body['csrf'] ?? ''))) amfa_webauthn_fail(403, 'csrf');

$display = $user . '@' . aegis_mfa_server_name();
echo json_encode(['ok' => true, 'options' => aegis_mfa_webauthn_creation_options($user, $display)]);
