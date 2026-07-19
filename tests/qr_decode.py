#!/usr/bin/env python3
# Aegis MFA - QR decoder cross-check, run after qr.test.php.
# Each dumped matrix must decode back to its exact input with OpenCV.
# exit 0 = all decoded, 1 = any failure, 2 = cv2 unavailable (skip)
import json, sys, tempfile, os

try:
    import numpy as np
    import cv2
except ImportError:
    print("qr_decode: cv2/numpy not available, skipping cross-check")
    sys.exit(2)

path = os.path.join(tempfile.gettempdir(), 'aegis_qr_dump.json')
if not os.path.exists(path):
    print("qr_decode: no dump found, run tests/qr.test.php first")
    sys.exit(1)

cases = json.load(open(path))
scale, quiet = 8, 4
det = cv2.QRCodeDetector()
fails = 0
for name, c in cases.items():
    mat = c['matrix']; n = len(mat)
    dim = (n + 2 * quiet) * scale
    img = np.full((dim, dim), 255, np.uint8)
    for r in range(n):
        for col in range(n):
            if mat[r][col] == '1':
                y = (r + quiet) * scale; x = (col + quiet) * scale
                img[y:y + scale, x:x + scale] = 0
    data, _, _ = det.detectAndDecode(img)
    ok = (data == c['data'])
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}")
    if not ok:
        fails += 1
        print(f"        got: {data[:60]!r}")

print("\nqr_decode: ALL DECODED OK" if fails == 0 else f"\nqr_decode: {fails} FAILED")
sys.exit(0 if fails == 0 else 1)
