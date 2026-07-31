<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

// the code is meant to run warning-free, so a notice from any suite is a failed test
error_reporting(E_ALL);
ini_set('display_errors', '1');

set_error_handler(function (int $no, string $msg, string $file, int $line): bool {
    // @-suppressed expressions drop out of error_reporting, those are deliberate
    if (!(error_reporting() & $no)) return true;
    fwrite(STDERR, "FAIL  php diagnostic: $msg  (" . basename($file) . ":$line)\n");
    exit(1);
});
