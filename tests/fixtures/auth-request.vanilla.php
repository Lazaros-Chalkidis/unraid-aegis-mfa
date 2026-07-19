<?php
// only start the session if a session cookie exists
if (isset($_COOKIE[session_name()])) {
  session_start();
  // authorized?
  if (isset($_SESSION["unraid_login"])) {
    if (time() - $_SESSION['unraid_login'] > 300) {
      $_SESSION['unraid_login'] = time();
    }
    session_write_close();
    http_response_code(200);
    exit;
  }
  session_write_close();
}

function isPathInDocroot(string $realPath, string $docroot): bool {
  return $realPath === $docroot || str_starts_with($realPath, $docroot . '/');
}

function getRequestUriPath(): string {
  $requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
  return is_string($requestUri) ? $requestUri : '/';
}

$docroot = '/usr/local/emhttp';
$requestUri = getRequestUriPath();

// non-authorized
http_response_code(401);
exit;
