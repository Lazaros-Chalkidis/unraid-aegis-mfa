#!/bin/bash
# runs the pure-bash recovery against real patched fixtures, both the backup-restore
# path and the sed-strip fallback, so a marker or path change cannot silently break it
set -u
pass=0; fail=0
t() { if [ "$2" = "0" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL  $1"; fi; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/source"
FX="$ROOT/tests/fixtures"
SCRIPT="$SRC/scripts/aegis-mfa-recover.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
EMH="$WORK/emhttp"
FLASH="$WORK/flash"
mkdir -p "$EMH/webGui/include" "$FLASH"

# a copy of the script with the two roots redirected into the sandbox
SB="$WORK/recover.sh"
sed -e "s#^EMHTTP=.*#EMHTTP=\"$EMH\"#" \
    -e "s#^FLASH=.*#FLASH=\"$FLASH\"#" \
    "$SCRIPT" > "$SB"
chmod +x "$SB"

# patched fixtures built the same way the installer does, via php
patch_fixtures() {
    cp "$FX/auth-request.vanilla.php" "$EMH/auth-request.php"
    cp "$FX/login.vanilla.php" "$EMH/webGui/include/.login.php"
    php -r '
      define("AEGIS_MFA_EMHTTP", $argv[1]);
      define("AEGIS_MFA_FLASH_DIR", $argv[2]);
      define("AEGIS_MFA_STATE_DIR", $argv[2]."/state");
      require $argv[3]."/include/AegisMfaInstall.php";
      $ok = true;
      foreach (aegis_mfa_patch_specs() as $s) { if (!aegis_mfa_patch_file($s)) $ok = false; }
      exit($ok ? 0 : 1);
    ' "$EMH" "$FLASH" "$SRC"
}

A_VAN=$(md5sum "$FX/auth-request.vanilla.php" | cut -d' ' -f1)
L_VAN=$(md5sum "$FX/login.vanilla.php" | cut -d' ' -f1)

# path 1: backups present, byte-identical restore
patch_fixtures
t "path1 patched auth"  "$(grep -qc AEGIS_MFA_HOOK_BEGIN "$EMH/auth-request.php" >/dev/null; grep -q AEGIS_MFA_HOOK_BEGIN "$EMH/auth-request.php" && echo 0 || echo 1)"
bash "$SB" >/dev/null 2>&1
t "path1 auth restored byte-identical"  "$([ "$(md5sum "$EMH/auth-request.php" | cut -d' ' -f1)" = "$A_VAN" ] && echo 0 || echo 1)"
t "path1 login restored byte-identical" "$([ "$(md5sum "$EMH/webGui/include/.login.php" | cut -d' ' -f1)" = "$L_VAN" ] && echo 0 || echo 1)"
t "path1 flag set"      "$([ -f "$FLASH/DISABLE.flag" ] && echo 0 || echo 1)"
t "path1 backups gone"  "$([ ! -f "$EMH/auth-request.php.aegis-bak" ] && echo 0 || echo 1)"

# path 2: backups removed, sed-strip still yields valid vanilla
rm -f "$FLASH/DISABLE.flag"
patch_fixtures
find "$EMH" -name '*.aegis-bak' -delete
bash "$SB" >/dev/null 2>&1
t "path2 auth marker-free"  "$(grep -q AEGIS_MFA_HOOK "$EMH/auth-request.php" && echo 1 || echo 0)"
t "path2 login marker-free" "$(grep -q AEGIS_MFA_HOOK "$EMH/webGui/include/.login.php" && echo 1 || echo 0)"
t "path2 auth valid php"    "$(php -l "$EMH/auth-request.php" >/dev/null 2>&1 && echo 0 || echo 1)"
t "path2 login valid php"   "$(php -l "$EMH/webGui/include/.login.php" >/dev/null 2>&1 && echo 0 || echo 1)"
t "path2 auth byte-identical to vanilla"  "$([ "$(md5sum "$EMH/auth-request.php" | cut -d' ' -f1)" = "$A_VAN" ] && echo 0 || echo 1)"

# path 3: idempotent on already-clean files
rm -f "$FLASH/DISABLE.flag"
bash "$SB" >/dev/null 2>&1
t "path3 idempotent auth valid" "$(php -l "$EMH/auth-request.php" >/dev/null 2>&1 && echo 0 || echo 1)"
t "path3 flag set again"        "$([ -f "$FLASH/DISABLE.flag" ] && echo 0 || echo 1)"

# path 4: a missing login file is skipped, not fatal
rm -f "$FLASH/DISABLE.flag"
rm -f "$EMH/webGui/include/.login.php"
bash "$SB" >/dev/null 2>&1
rc=$?
t "path4 missing file non-fatal" "$([ "$rc" -eq 0 ] && echo 0 || echo 1)"

echo "recover.test.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
