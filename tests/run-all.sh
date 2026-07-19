#!/bin/bash
# Aegis MFA - run every test suite.
# exit 0 = all passed or skipped for missing PHP, 1 = a suite failed, 2 = could not run

cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")/.." || exit 2

if ! command -v php >/dev/null 2>&1; then
    echo "php not found: skipping the PHP test suites."
    echo "Install PHP CLI to run them, or run them on the Unraid box."
    exit 0
fi

fail=0
for suite in tests/*.test.php; do
    [ -f "$suite" ] || continue
    echo "### $suite"
    php "$suite" || fail=1
    echo
done

# the QR cross-check needs python3 with OpenCV, missing or broken python is a skip.
# The probe is explicit, on Windows python3 can be a stub that does nothing
if python3 -c "import cv2, numpy" >/dev/null 2>&1; then
    echo "### tests/qr_decode.py"
    python3 tests/qr_decode.py
    [ "$?" -eq 1 ] && fail=1
    echo
else
    echo "### tests/qr_decode.py - skipped (needs python3 with opencv)"
    echo
fi

# pure-bash recovery test, php is only needed to build the patched fixtures
echo "### tests/recover.test.sh"
bash tests/recover.test.sh
[ "$?" -eq 0 ] || fail=1
echo

if [ "$fail" -eq 0 ]; then
    echo "ALL SUITES PASSED"
else
    echo "SOME SUITES FAILED"
fi
exit $fail
