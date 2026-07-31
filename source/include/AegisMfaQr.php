<?php
/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

require_once __DIR__ . '/vendor/qrcode.php';

// past its capacity table the vendored library ends in E_USER_ERROR, which no try/catch holds. 311 = version 10 at level M
function aegis_qr_max_bytes(): int {
    return 311;
}

// thin wrapper over the vendored MIT library, the secret is rendered locally and never leaves the box
function aegis_qr_encode(string $data): array {
    if ($data === '' || strlen($data) > aegis_qr_max_bytes()) return [];
    $qr = QRCode::getMinimumQRCode($data, QR_ERROR_CORRECT_LEVEL_M);
    $n = $qr->getModuleCount();
    $m = [];
    for ($r = 0; $r < $n; $r++) {
        $row = [];
        for ($c = 0; $c < $n; $c++) $row[] = $qr->isDark($r, $c) ? 1 : 0;
        $m[] = $row;
    }
    return $m;
}

function aegis_qr_svg(array $m, int $scale = 6, int $quiet = 4): string {
    $n = count($m);
    if ($n === 0) return '';
    $dim = ($n + 2 * $quiet) * $scale;
    $svg  = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $dim . '" height="' . $dim . '" '
          . 'viewBox="0 0 ' . $dim . ' ' . $dim . '" shape-rendering="crispEdges">';
    $svg .= '<rect width="' . $dim . '" height="' . $dim . '" fill="#ffffff"/>';
    $svg .= '<path fill="#000000" d="';
    for ($r = 0; $r < $n; $r++) {
        for ($c = 0; $c < $n; $c++) {
            if ($m[$r][$c]) {
                $x = ($c + $quiet) * $scale;
                $y = ($r + $quiet) * $scale;
                $svg .= "M$x $y h$scale v$scale h-$scale z ";
            }
        }
    }
    $svg .= '"/></svg>';
    return $svg;
}
