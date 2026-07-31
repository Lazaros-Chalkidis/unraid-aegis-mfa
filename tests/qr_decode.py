#!/usr/bin/env python3
# ============================================================================
# AEGIS MFA
# Copyright (C) 2026 Lazaros Chalkidis
# License: GPLv3
# =========================================================================

# cross-check after qr.test.php: every dumped matrix must decode back to its exact
# input with OpenCV. exit 0 = all decoded, 1 = failure, 2 = cv2 missing (skip)
import json, sys, tempfile, os

try:
    import numpy as np
except ImportError:
    print("qr_decode: numpy not available, skipping cross-check")
    sys.exit(2)

# zxing-cpp first: opencv's detector misreads roughly 3% of valid codes at this size,
# which made the suite fail at random. opencv stays as a fallback, retried at a larger scale
try:
    import zxingcpp
except ImportError:
    zxingcpp = None
try:
    import cv2
except ImportError:
    cv2 = None
if zxingcpp is None and cv2 is None:
    print("qr_decode: no decoder available, skipping cross-check")
    sys.exit(2)

path = os.path.join(tempfile.gettempdir(), 'aegis_qr_dump.json')
if not os.path.exists(path):
    print("qr_decode: no dump found, run tests/qr.test.php first")
    sys.exit(1)

cases = json.load(open(path))
quiet = 4


def render(mat, scale):
    n = len(mat)
    dim = (n + 2 * quiet) * scale
    img = np.full((dim, dim), 255, np.uint8)
    for r in range(n):
        for col in range(n):
            if mat[r][col] == '1':
                y = (r + quiet) * scale
                x = (col + quiet) * scale
                img[y:y + scale, x:x + scale] = 0
    return img


def decodes(mat, want):
    if zxingcpp is not None:
        res = zxingcpp.read_barcode(render(mat, 8))
        return res is not None and res.text == want
    det = cv2.QRCodeDetector()
    for scale in (8, 16):
        data, _, _ = det.detectAndDecode(render(mat, scale))
        if data == want:
            return True
    return False


print("qr_decode: using " + ("zxing-cpp" if zxingcpp is not None else "opencv"))
fails = 0
for name, c in cases.items():
    ok = decodes(c['matrix'], c['data'])
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}")
    if not ok:
        fails += 1
        print(f"        got: {data[:60]!r}")

print("\nqr_decode: ALL DECODED OK" if fails == 0 else f"\nqr_decode: {fails} FAILED")
sys.exit(0 if fails == 0 else 1)
