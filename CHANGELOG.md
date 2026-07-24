
# Aegis MFA

## Version 2026.07.24

### Fixed
- Wording changes for clearer phrasing

## Version 2026.07.21

### Fixed
- Support links now point to GitHub Issues, and the README wording was tightened

## Version 2026.07.19

### First release
- TOTP two-factor authentication for the Unraid webGUI, on top of the existing password login
- Any authenticator app works: Google Authenticator, Authy, Bitwarden, whatever you already use
- Per account: every account the webGUI accepts enrols with its own secret and its own backup codes. On current Unraid that is normally just root
- Setup wizard: scan a QR, confirm a code, save ten backup codes and type one back to finish
- The QR is generated on the server, the secret never leaves the machine
- Ten single-use backup codes, hashed on disk, with a remaining count in the settings
- Trusted LAN: no code prompt from networks you list, the password is still required. Your own address is shown ready to add
- Grace period: a new account gets a set number of days to enrol before setup becomes mandatory
- Dry-run: for the first 24 hours nothing is blocked, you see the prompts and failures are only logged, then you enforce when ready
- Lockout: repeated wrong codes lock the source IP out. Counters live in RAM, so brute force never wears the flash drive
- A code that was already used is refused, even inside its own 30-second window
- A failed code shows the server's own time, the usual culprit when codes suddenly stop matching
- Per-account admin actions on the settings page: one-time setup link, fresh backup codes, reset
- Fail-open by design: whatever breaks, corrupt config, a missing file, an Unraid update, the result is password-only login, never a locked door
- The two Unraid login files are checked before they are touched, an unrecognised layout is refused instead of guessed at
- Self-healing: a boot hook and a ten-minute cron re-apply the login patches if an Unraid update removes them
- An Unraid notification fires when MFA is on but the patches are missing, and once more when protection returns
- Ways back in: backup codes, `aegis-mfa disable` over SSH, a `DISABLE.flag` file on the flash, or `recover.sh` on the flash, pure bash, works even with PHP broken
- CLI: `aegis-mfa` covers status, enable, disable, enforce and a preflight report that rehearses the patches before you enable anything
- Every success and failure lands in the syslog with the account and the source IP
- The challenge and the wizard match the Unraid login card, the settings follow the Aegis styling, all four webGUI themes supported
- A notice warns when your Unraid release has not been tested with the plugin yet
- Needs Unraid 7.3.1 or newer, enforced at install
