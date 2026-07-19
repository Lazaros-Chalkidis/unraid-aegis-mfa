#!/bin/bash
# Aegis MFA - last-resort recovery, pure bash, no PHP.
# For when the login is broken and even aegis-mfa disable will not run.
#
#   bash /boot/config/plugins/aegis.mfa/recover.sh
#
# Restores the backups byte-for-byte (or sed-strips the hooks), then drops
# DISABLE.flag so the plugin stays off after a reboot. Never touches secrets
# or settings, re-enable later from the settings page.

set -u

EMHTTP="/usr/local/emhttp"
FLASH="/boot/config/plugins/aegis.mfa"
AUTH="${EMHTTP}/auth-request.php"
LOGIN="${EMHTTP}/webGui/include/.login.php"
BEGIN="// AEGIS_MFA_HOOK_BEGIN"
END="// AEGIS_MFA_HOOK_END"

say() { printf '%s\n' "$*"; }

# restore one file: prefer the backup, fall back to sed-stripping, verify no marker remains
restore_one() {
    local f="$1" bak="$1.aegis-bak"

    if [[ ! -e "$f" ]]; then
        say "  $f: not present, skipping"
        return 0
    fi

    if [[ -f "$bak" ]]; then
        if cp -f "$bak" "$f"; then
            rm -f "$bak"
            say "  $f: restored from backup"
        else
            say "  $f: FAILED to restore from backup"
            return 1
        fi
    elif grep -q "AEGIS_MFA_HOOK_BEGIN" "$f" 2>/dev/null; then
        # no backup, markers present: delete the block including both marker lines.
        # the markers contain //, so the sed range uses \|...\| delimiters
        local tmp="${f}.aegis-recover"
        if sed '\|AEGIS_MFA_HOOK_BEGIN|,\|AEGIS_MFA_HOOK_END|d' "$f" > "$tmp" 2>/dev/null && [[ -s "$tmp" ]]; then
            # write in place via cat to keep mode and owner
            if cat "$tmp" > "$f"; then
                rm -f "$tmp"
                say "  $f: hook stripped in place"
            else
                rm -f "$tmp"
                say "  $f: FAILED to write stripped file"
                return 1
            fi
        else
            rm -f "$tmp"
            say "  $f: FAILED to strip hook"
            return 1
        fi
    else
        say "  $f: already clean"
        return 0
    fi

    if grep -q "AEGIS_MFA_HOOK_BEGIN" "$f" 2>/dev/null; then
        say "  $f: WARNING, a marker still remains, check the file by hand"
        return 1
    fi
    return 0
}

say "Aegis MFA recovery"
say "------------------"

rc=0
restore_one "$AUTH"  || rc=1
restore_one "$LOGIN" || rc=1

# disable the plugin so a reboot does not re-apply the hook
if mkdir -p "$FLASH" 2>/dev/null && : > "$FLASH/DISABLE.flag" 2>/dev/null; then
    say "  DISABLE.flag set, MFA will stay off after reboot"
else
    say "  WARNING, could not write DISABLE.flag at $FLASH"
    rc=1
fi

# best-effort opcache clear if a working php is around, the files on disk are already fixed
for p in /usr/bin/php /usr/local/bin/php; do
    [[ -x "$p" ]] && "$p" -r 'function_exists("opcache_reset") && opcache_reset();' >/dev/null 2>&1 && break
done

say "------------------"
if [[ $rc -eq 0 ]]; then
    say "Done. The Unraid login files are stock and MFA is disabled."
    say "Log in with your password. Re-enable from Settings > Aegis MFA when ready."
else
    say "Finished with warnings. If the login is still broken, the two files are:"
    say "  $AUTH"
    say "  $LOGIN"
    say "Remove any block between $BEGIN and $END by hand, then reboot."
fi
exit $rc
