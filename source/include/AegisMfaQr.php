<?php
/*
 * Aegis MFA for Unraid - QR wrapper
 * Copyright (C) 2026 Lazaros Chalkidis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Thin wrapper over the vendored MIT QRCode library (include/vendor/
 * qrcode.php, (c) 2009 Kazuhiko Arase). The TOTP secret is turned into a
 * QR entirely locally and is never sent to any external service.
 *
 * Exposes the same two entry points the rest of the plugin uses:
 *   aegis_qr_encode($data) -> boolean matrix (1 = dark module)
 *   aegis_qr_svg($matrix)  -> standalone SVG string
 */

require_once __DIR__ . '/vendor/qrcode.php';

// encode payload into a boolean matrix at EC level M
function aegis_qr_encode(string $data): array {
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

// render the matrix as a crisp dependency-free SVG, $quiet in modules (spec minimum 4)
function aegis_qr_svg(array $m, int $scale = 6, int $quiet = 4): string {
    $n = count($m);
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
