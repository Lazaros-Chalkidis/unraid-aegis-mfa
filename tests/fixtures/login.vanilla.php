<?php
// Only start a session to check if they have a cookie that looks like our session
$server_name = strtok($_SERVER['HTTP_HOST'], ":");
if (!empty($_COOKIE['unraid_' . md5($server_name)])) {
    // Start the session so we can check if $_SESSION has data
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    // Check if the user is already logged in
    if ($_SESSION && !empty($_SESSION['unraid_user'])) {
        // Redirect the user to the start page
        header("Location: /" . $start_page);
        exit;
    }
}
function readFromFile($file): string
{
    $text = "";
    if (file_exists($file) && filesize($file) > 0) {
        $fp = fopen($file, "r");
        if (flock($fp, LOCK_EX)) {
            $text = fread($fp, filesize($file));
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }
    return $text;
}
// ... login form rendering and POST handling omitted ...
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // ... validate credentials ...
        $_SESSION['unraid_user'] = $username;
        session_write_close();
        my_logger("Successful login user {$username} from {$remote_addr}");

        // Redirect the user to the start page
        header("Location: /" . $start_page);
        exit;
    } catch (Exception $exception) {
        // ... show error ...
    }
}
?>
