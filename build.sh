#!/bin/bash
# ============================================================================
# AEGIS MFA
# Copyright (C) 2026 Lazaros Chalkidis
# License: GPLv3
# =========================================================================

# packages source/ into a .txz and writes the .plg
#
# Usage:
#   ./build.sh                        release build (today's date, main branch)
#   ./build.sh a                      versioned suffix: 2026.01.15a
#   ./build.sh a dev                  dev build (dev branch)
#   ./build.sh "" local               local build (embeds .txz in .plg, no URL)
#   ./build.sh a dev local            dev + local
#
# Output:
#   packages/aegis.mfa-<version>.txz
#   aegis.mfa.plg

# Configuration
PLUGIN_NAME="aegis.mfa"
AUTHOR="Lazaros Chalkidis"
GITHUB_USER="Lazaros-Chalkidis"
GIT_URL="https://github.com/Lazaros-Chalkidis/unraid-aegis-mfa"
RAW_URL="${GIT_URL/github.com/raw.githubusercontent.com}"
PACKAGE_DIR_FINAL="packages"
PACKAGE_DIR_TEMP="package-temp"
MIN_UNRAID="7.3.1"

# Versioning
BASE_VERSION=$(date +'%Y.%m.%d')
LETTER_SUFFIX="${1}"
STAGE_INPUT="${2}"
LOCAL_INSTALL="${3:-}"

# local can sit in the 2nd or 3rd positional, both documented forms work
if [[ "$STAGE_INPUT" == "local" ]]; then
    LOCAL_INSTALL="local"
    STAGE_INPUT=""
fi

# these land in XML attributes in the .plg, so a quote or an ampersand here is code, not a typo
case "$LETTER_SUFFIX" in
    ""|[a-z]) ;;
    *) echo "Suffix must be empty or one lowercase letter (a-z). Refusing to build."; exit 1 ;;
esac
case "$STAGE_INPUT" in
    ""|dev|release) ;;
    *) echo "Stage must be empty, 'dev' or 'release'. Refusing to build."; exit 1 ;;
esac
case "$LOCAL_INSTALL" in
    ""|local) ;;
    *) echo "Third argument must be empty or 'local'. Refusing to build."; exit 1 ;;
esac

STAGE_SUFFIX=""
if [[ -n "$STAGE_INPUT" && "$STAGE_INPUT" != "release" ]]; then
    STAGE_SUFFIX="-${STAGE_INPUT}"
fi
VERSION="${BASE_VERSION}${LETTER_SUFFIX}${STAGE_SUFFIX}"

# Branch and URL
if [[ "$LOCAL_INSTALL" == "local" ]]; then
    BRANCH="local"
    PLUGIN_URL_STRUCTURE=""
    CHANGES_TEXT="- Local build (embedded package; no URL download)."
elif [[ "$STAGE_INPUT" == "dev" ]]; then
    BRANCH="dev"
    PLUGIN_URL_STRUCTURE="&gitURL;/raw/&branch;/packages/&name;-&version;.txz"
    CHANGES_TEXT="- Development build from the 'dev' branch. For testing only."
else
    BRANCH="main"
    PLUGIN_URL_STRUCTURE="&gitURL;/releases/download/&version;/&name;-&version;.txz"
    CHANGES_TEXT="- Automated release build."
fi

# Changelog
CHANGELOG_MD_FILE="CHANGELOG.md"
if [[ -f "$CHANGELOG_MD_FILE" ]]; then
    # a CDATA terminator in here closes the block early and the rest becomes real elements, run as root
    if grep -qF ']]>' "$CHANGELOG_MD_FILE"; then
        echo "CHANGELOG.md contains ']]>' which would break out of the CDATA block."
        echo "Remove it. Refusing to build."
        exit 1
    fi
    CHANGES_BLOCK="$(cat "$CHANGELOG_MD_FILE")"
else
    CHANGES_BLOCK="### ${VERSION}
${CHANGES_TEXT}"
fi

# Build
echo "=============================================="
echo " Aegis MFA build"
echo " Version : ${VERSION}"
echo " Branch  : ${BRANCH}"
echo "=============================================="

# a build that cannot pass its own tests must not ship, this plugin patches the login path.
# Without PHP CLI (a Windows checkout) they are skipped with a warning, SKIP_TESTS=1 skips deliberately.
if [[ "${SKIP_TESTS}" == "1" ]]; then
    echo "SKIP_TESTS=1 - test suite skipped by request."
elif ! command -v php &>/dev/null; then
    echo "----------------------------------------------------"
    echo " php not found on this machine: tests were SKIPPED."
    echo " The package is built, but nothing has verified it."
    echo " Run ./tests/run-all.sh where PHP is available"
    echo " (the Unraid box will do) before you publish."
    echo "----------------------------------------------------"
elif [[ -f tests/run-all.sh ]]; then
    echo "Running test suite..."
    if ! bash tests/run-all.sh > /tmp/aegis-mfa-tests.log 2>&1; then
        echo "TESTS FAILED - build aborted. See /tmp/aegis-mfa-tests.log"
        tail -20 /tmp/aegis-mfa-tests.log
        exit 1
    fi
    echo "Tests passed: $(grep -c 'passed, 0 failed' /tmp/aegis-mfa-tests.log) suites"
fi

rm -rf "${PACKAGE_DIR_TEMP}" "${PACKAGE_DIR_FINAL}"
mkdir -p "${PACKAGE_DIR_TEMP}" "${PACKAGE_DIR_FINAL}"

PLUGIN_DEST="${PACKAGE_DIR_TEMP}/usr/local/emhttp/plugins/${PLUGIN_NAME}"
mkdir -p "${PLUGIN_DEST}"
cp -R source/* "${PLUGIN_DEST}/"

# stamp the running build version at the installed location, not stale .plg metadata
echo "${VERSION}" > "${PLUGIN_DEST}/VERSION"

# ship the tested-release baseline when the repo carries one, the install merge is a no-op without it

# branch metadata, readable by PHP
cat > "${PLUGIN_DEST}/branch.meta" << METAEOF
BRANCH="${BRANCH}"
IS_MAIN_BRANCH=$([[ "$BRANCH" == "main" ]] && echo "1" || echo "0")
METAEOF

# a Windows checkout can hand us CRLF: a CR on a shebang means bad interpreter, a CR in the
# cron file makes crond skip the entry. strip CR from all text, images are left alone
find "${PLUGIN_DEST}" -type f ! -name "*.png" -exec sed -i 's/\r$//' {} \;

# no-extension files are chmodded by name, emhttpd only runs an executable hook.
# The PLG repeats these on the box, so a Windows build host still produces a working plugin
find "${PLUGIN_DEST}" -type d      -exec chmod 755 {} \;
find "${PLUGIN_DEST}" -type f      -exec chmod 644 {} \;
find "${PLUGIN_DEST}" -name "*.sh" -exec chmod 755 {} \;
chmod 755 "${PLUGIN_DEST}/event/started"
chmod 755 "${PLUGIN_DEST}/scripts/aegis-mfa"
chmod 755 "${PLUGIN_DEST}/scripts/aegis-mfa-cron"

# Create .txz
FILENAME="${PLUGIN_NAME}-${VERSION}"
PACKAGE_PATH="${PACKAGE_DIR_FINAL}/${FILENAME}.txz"

echo "Creating package: ${FILENAME}.txz ..."
tar -C "${PACKAGE_DIR_TEMP}" -cJf "${PACKAGE_PATH}" usr

if [[ ! -f "${PACKAGE_PATH}" ]]; then
    echo "Package creation failed!"
    exit 1
fi
echo "Package: $(du -h "${PACKAGE_PATH}" | cut -f1)  ->  ${PACKAGE_PATH}"

# MD5
if command -v md5sum &>/dev/null; then
    PACKAGE_MD5="$(md5sum "${PACKAGE_PATH}" | cut -d' ' -f1)"
elif command -v md5 &>/dev/null; then
    PACKAGE_MD5="$(md5 -q "${PACKAGE_PATH}")"
else
    echo "md5sum/md5 not found - MD5 will be empty in PLG!"
    PACKAGE_MD5=""
fi
echo "MD5: ${PACKAGE_MD5}"

# Base64 helper (portable)
b64_nolf() {
    if base64 --help 2>/dev/null | grep -q -- "-w"; then
        base64 -w 0 "$1"
    else
        base64 "$1" | tr -d '\n'
    fi
}

# Shared PLG sections
PLG_DESCRIPTION="Two-factor authentication for the Unraid webGUI. TOTP codes from any authenticator app, per user, with backup codes, trusted LAN bypass, and lockout protection. Fail-open by design: a fault can never lock you out."

# refuses anything below the minimum: the architecture is confirmed on 7.3.1+ only. runs before the package lands.
# NOTE: no bare "&&" in any INLINE block, the body is parsed as XML text and a raw ampersand is invalid.
PLG_VERSION_GATE='UNRAID_VER=$(sed -n "s/^version=\"\(.*\)\"/\1/p" /etc/unraid-version 2>/dev/null)
MIN_VER="'"${MIN_UNRAID}"'"
if [ -z "$UNRAID_VER" ]; then
    echo "Cannot read /etc/unraid-version. Installation aborted."
    exit 1
fi
LOWEST=$(printf "%s\n%s\n" "$UNRAID_VER" "$MIN_VER" | sort -V | head -1)
TOO_OLD=0
if [ "$UNRAID_VER" != "$MIN_VER" ]; then
    if [ "$LOWEST" != "$MIN_VER" ]; then
        TOO_OLD=1
    fi
fi
if [ "$TOO_OLD" = "1" ]; then
    echo ""
    echo "----------------------------------------------------"
    echo " Aegis MFA requires Unraid ${MIN_VER} or newer."
    echo " This server runs ${UNRAID_VER}."
    echo ""
    echo " Older releases ship different PHP and nginx internals,"
    echo " and this plugin patches the login path. Installing on"
    echo " an unverified base is not safe, so it is refused."
    echo ""
    echo " Installation aborted. Nothing was changed."
    echo "----------------------------------------------------"
    echo ""
    exit 1
fi'

PLG_INSTALL_SCRIPT='# Fix ownership and permissions
chown -R root:root /usr/local/emhttp/plugins/&name;
find /usr/local/emhttp/plugins/&name; -type d -exec chmod 755 {} \;
find /usr/local/emhttp/plugins/&name; -type f -exec chmod 644 {} \;
find /usr/local/emhttp/plugins/&name; -name "*.sh" -exec chmod 755 {} \;

# no-extension files chmodded by name, emhttpd only runs an executable hook
chmod 755 /usr/local/emhttp/plugins/&name;/event/started
chmod 755 /usr/local/emhttp/plugins/&name;/scripts/aegis-mfa
chmod 755 /usr/local/emhttp/plugins/&name;/scripts/aegis-mfa-cron

# the CLI on PATH is how a locked-out admin gets back in: ssh, then aegis-mfa disable
ln -sf /usr/local/emhttp/plugins/&name;/scripts/aegis-mfa /usr/local/sbin/aegis-mfa

# second re-apply mechanism next to the boot hook. no dot in the filename, cron.d skips dotted files on some builds
install -m 0644 /usr/local/emhttp/plugins/&name;/&name;.cron /etc/cron.d/aegis-mfa
/etc/rc.d/rc.crond restart >/dev/null 2>/dev/null

# first install only, an upgrade leaves the existing config exactly as it is. no merge step,
# the PHP layer deep-merges defaults at read time. copied from the package, a heredoc is not valid XML here
mkdir -p /boot/config/plugins/&name;
if [ ! -f /boot/config/plugins/&name;/config.json ]; then
    cp /usr/local/emhttp/plugins/&name;/config.default.json /boot/config/plugins/&name;/config.json
fi

# secrets.json is never written here, an upgrade must not touch a single byte of it

# unraid reinstalls from the local package at boot, so the current one stays and older ones go
for pkg in /boot/config/plugins/&name;/&name;-*.txz; do
  if [ -f "$pkg" ]; then
    if [ "$pkg" != "/boot/config/plugins/&name;/&name;-&version;.txz" ]; then
      rm -f "$pkg"
      echo " Removed old package $(basename "$pkg")."
    fi
  fi
done

# leftover from the removed checksum list, plugin-managed and unread. logged, not removed quietly
if [ -f /boot/config/plugins/&name;/compat.json ]; then
    rm -f /boot/config/plugins/&name;/compat.json
    logger -t aegis-mfa "removed obsolete compat.json from the boot device"
    echo " Removed obsolete compat.json (tested-release list, no longer used)."
fi

# the pure-bash recovery script goes on the flash: reachable with the plugin folder gone,
# working with PHP broken. overwritten every install to stay current
cp -f /usr/local/emhttp/plugins/&name;/scripts/aegis-mfa-recover.sh \
      /boot/config/plugins/&name;/recover.sh 2>/dev/null
chmod 0755 /boot/config/plugins/&name;/recover.sh 2>/dev/null

# reset opcache so the login path runs the upgraded files, not stale bytecode
php -r "if (function_exists(\"opcache_reset\")) opcache_reset();" >/dev/null 2>/dev/null


# bring the patches in line with the saved setting: no-op on first install, on an upgrade with MFA
# on it re-points the hooks at this build. anything off removes the patches, never half-wired
php -r "require \"/usr/local/emhttp/plugins/&name;/include/AegisMfaInstall.php\"; \$r = aegis_mfa_reconcile_patches(); echo \"patch state: \" . (\$r[\"state\"] ?? \"unknown\") . PHP_EOL;" 2>/dev/null

echo ""
echo "----------------------------------------------------"
echo " &name; (&branch; build) installed successfully."
echo " Version : &version;"
echo " Settings: Settings > Aegis MFA"
echo ""
echo " MFA is OFF until you enable it. Enabling starts a"
echo " 24h dry-run so you can confirm it works before it"
echo " is enforced."
echo ""
echo " Locked out? From SSH or the console:  aegis-mfa disable"
echo "----------------------------------------------------"
echo ""'

# order matters: the patches must come out while the code that removes them still exists.
# Deleting the folder first would strand the hooks in Unraid core files
PLG_REMOVE_SCRIPT='# 1. Un-patch the login files FIRST, while our code still exists, and turn the saved switch off with them
SWITCH_OFF=0
if [[ -f /usr/local/emhttp/plugins/&name;/include/AegisMfaInstall.php ]]; then
    if php -r "require \"/usr/local/emhttp/plugins/&name;/include/AegisMfaInstall.php\"; require \"/usr/local/emhttp/plugins/&name;/include/AegisMfaAdmin.php\"; \$r = aegis_mfa_uninstall(); echo \"login files restored: \" . (\$r[\"state\"] ?? \"unknown\") . PHP_EOL; exit(aegis_mfa_set_enabled(false) ? 0 : 1);" 2>/dev/null; then
        SWITCH_OFF=1
    fi
fi

# 2. drop the CLI symlink and the cron entry
rm -f /usr/local/sbin/aegis-mfa
rm -f /etc/cron.d/aegis-mfa
/etc/rc.d/rc.crond restart >/dev/null 2>/dev/null

# 3. drop the in-RAM lockout counters
rm -rf /var/local/&name;

# 4. now the package and the plugin folder can go
removepkg &name;-&version;
rm -rf /usr/local/emhttp/plugins/&name;

# 5. only our own files leave the boot device: one unconfirmed click is not consent to drop enrolments
rm -f /boot/config/plugins/&name;/recover.sh
rm -f /boot/config/plugins/&name;/&name;-*.txz
rm -f /boot/config/plugins/&name;/lockouts.json

# the flag is the fallback for a switch we could not write, so it only stays behind when PHP did not run
if [[ "$SWITCH_OFF" == "1" ]]; then
    rm -f /boot/config/plugins/&name;/DISABLE.flag
fi
rmdir /boot/config/plugins/&name; 2>/dev/null

# clear opcache so the restored login files are the ones that run
php -r "if (function_exists(\"opcache_reset\")) opcache_reset();" >/dev/null 2>/dev/null

echo ""
echo "----------------------------------------------------"
echo " &name; has been removed."
echo " The Unraid login files were restored to stock and"
echo " password-only login is active again."
echo ""
echo " Your settings and 2FA enrolments were left in place:"
echo "   /boot/config/plugins/&name;/"
echo " A reinstall picks them up, with MFA switched off until"
echo " you turn it back on. To erase them instead, including"
echo " the TOTP secrets and the backup codes:"
echo "   rm -rf /boot/config/plugins/&name;"
echo "----------------------------------------------------"
echo ""'

# Generate .plg
echo "Generating ${PLUGIN_NAME}.plg (${BRANCH} target)..."

if [[ "$LOCAL_INSTALL" == "local" ]]; then
    PACKAGE_B64="$(b64_nolf "${PACKAGE_PATH}")"

    cat > "${PLUGIN_NAME}.plg" << EOF
<?xml version='1.0' standalone='yes'?>
<!DOCTYPE PLUGIN [
 <!ENTITY name    "${PLUGIN_NAME}">
 <!ENTITY author  "${AUTHOR}">
 <!ENTITY version "${VERSION}">
 <!ENTITY branch  "${BRANCH}">
 <!ENTITY gitURL  "${GIT_URL}">
 <!ENTITY selfURL "${RAW_URL}/&branch;/&name;.plg">
 <!ENTITY launch  "Settings/AegisMfa">
]>

<PLUGIN name="&name;" Title="Aegis MFA" author="&author;" version="&version;"
        pluginURL="&selfURL;" launch="&launch;"
        icon="icon-aegismfa"
        min="${MIN_UNRAID}"
        support="${GIT_URL}/issues">

<DESCRIPTION>
<![CDATA[
${PLG_DESCRIPTION}
]]>
</DESCRIPTION>

<CHANGES>
<![CDATA[
${CHANGES_BLOCK}
]]>
</CHANGES>

<FILE Run="/bin/bash">
<INLINE>
${PLG_VERSION_GATE}
</INLINE>
</FILE>

<FILE Name="/boot/config/plugins/&name;/&name;-&version;.txz.b64">
  <INLINE>${PACKAGE_B64}</INLINE>
</FILE>

<FILE Run="/bin/bash">
<INLINE>
mkdir -p /boot/config/plugins/&name;
base64 -d /boot/config/plugins/&name;/&name;-&version;.txz.b64 \\
    > /boot/config/plugins/&name;/&name;-&version;.txz 2>/dev/null || \\
  base64 -D /boot/config/plugins/&name;/&name;-&version;.txz.b64 \\
    > /boot/config/plugins/&name;/&name;-&version;.txz
rm -f /boot/config/plugins/&name;/&name;-&version;.txz.b64
upgradepkg --install-new /boot/config/plugins/&name;/&name;-&version;.txz
</INLINE>
</FILE>

<FILE Run="/bin/bash">
<INLINE>
${PLG_INSTALL_SCRIPT}
</INLINE>
</FILE>

<FILE Run="/bin/bash" Method="remove">
<INLINE>
${PLG_REMOVE_SCRIPT}
</INLINE>
</FILE>

</PLUGIN>
EOF

else

    cat > "${PLUGIN_NAME}.plg" << EOF
<?xml version='1.0' standalone='yes'?>
<!DOCTYPE PLUGIN [
 <!ENTITY name      "${PLUGIN_NAME}">
 <!ENTITY author    "${AUTHOR}">
 <!ENTITY version   "${VERSION}">
 <!ENTITY branch    "${BRANCH}">
 <!ENTITY gitURL    "${GIT_URL}">
 <!ENTITY pluginURL "${PLUGIN_URL_STRUCTURE}">
 <!ENTITY selfURL   "${RAW_URL}/&branch;/&name;.plg">
 <!ENTITY md5       "${PACKAGE_MD5}">
 <!ENTITY launch    "Settings/AegisMfa">
]>

<PLUGIN name="&name;" Title="Aegis MFA" author="&author;" version="&version;"
        pluginURL="&selfURL;" launch="&launch;"
        icon="icon-aegismfa"
        min="${MIN_UNRAID}"
        support="${GIT_URL}/issues">

<DESCRIPTION>
<![CDATA[
${PLG_DESCRIPTION}
]]>
</DESCRIPTION>

<CHANGES>
<![CDATA[
${CHANGES_BLOCK}
]]>
</CHANGES>

<FILE Run="/bin/bash">
<INLINE>
${PLG_VERSION_GATE}
</INLINE>
</FILE>

<FILE Name="/boot/config/plugins/&name;/&name;-&version;.txz" Run="upgradepkg --install-new">
  <URL>&pluginURL;</URL>
  <MD5>&md5;</MD5>
</FILE>

<FILE Run="/bin/bash">
<INLINE>
${PLG_INSTALL_SCRIPT}
</INLINE>
</FILE>

<FILE Run="/bin/bash" Method="remove">
<INLINE>
${PLG_REMOVE_SCRIPT}
</INLINE>
</FILE>

</PLUGIN>
EOF

fi

# Cleanup
rm -rf "${PACKAGE_DIR_TEMP}"

# last gate: a .plg that does not parse, or grew a runner we did not write, must not ship
if [[ "$LOCAL_INSTALL" == "local" ]]; then EXPECTED_RUNNERS=4; else EXPECTED_RUNNERS=3; fi
if command -v php &>/dev/null && php -r 'exit(class_exists("DOMDocument") ? 0 : 1);'; then
    php -r '
        $f = $argv[1];
        libxml_use_internal_errors(true);
        $d = new DOMDocument();
        if (!$d->load($f)) {
            $e = libxml_get_errors();
            fwrite(STDERR, "PLG is not valid XML: " . trim($e[0]->message ?? "unknown") . PHP_EOL);
            exit(1);
        }
        $runners = 0;
        foreach ($d->getElementsByTagName("FILE") as $n) {
            if ($n->hasAttribute("Run") && $n->getElementsByTagName("INLINE")->length) $runners++;
        }
        if ($runners !== (int)$argv[2]) {
            fwrite(STDERR, "PLG has $runners inline script blocks, expected {$argv[2]}. Refusing." . PHP_EOL);
            exit(1);
        }
    ' "${PLUGIN_NAME}.plg" "${EXPECTED_RUNNERS}" || {
        rm -f "${PLUGIN_NAME}.plg"
        echo "Build aborted, the .plg was removed."
        exit 1
    }
else
    echo "Note: no DOMDocument here, the .plg was not parsed. Build again where PHP has ext-xml."
fi

# Summary
echo ""
echo "Build complete!"
echo "   Package : ${PACKAGE_PATH}  ($(du -h "${PACKAGE_PATH}" | cut -f1))"
echo "   PLG     : ${PLUGIN_NAME}.plg"
echo "   MD5     : ${PACKAGE_MD5}"
echo "   Version : ${VERSION}"
echo "   Branch  : ${BRANCH}"
echo "   Min     : Unraid ${MIN_UNRAID}"
echo ""
