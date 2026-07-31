
# Aegis MFA

## Version 2026.07.31

### Security
- The settings page now needs a code like every other page. It has the Disable button on it, so the password alone was enough to switch MFA off
- Every action on the settings page carries its own CSRF token
- Two copies of the same code sent at the same moment can no longer both get in
- Setup links and the account name in your authenticator no longer come from a header a visitor can set
- `aegis-mfa enforce` rejects anything that is not a plain number of hours
- The failure counter has an upper bound, so a flood from many addresses cannot fill memory

### Added
- Lockout history: a section listing blocked addresses with the failure count, when they were locked and how long is left. Unlock frees one now, Delete drops a spent row, Clear removes the expired ones
- Keep history switch: blocked addresses survive a reboot. Nothing is written while requests come in, the ten-minute cron saves a snapshot and only when something changed
- The page warns you when the browser you are on is on the trusted list, since an exempt browser looked exactly like a protected one
- Accounts that cannot sign in to the webGUI, share users, are marked as such and left out of the count.

### Changed
- New backup codes now work like the first set: shown once, downloadable, and confirmed by typing one back. Your current codes keep working until you confirm, so closing the page halfway no longer leaves you with none
- Uninstalling keeps your settings and enrolments, and takes only its own files. A reinstall picks them up with MFA switched off. The command to erase everything is printed at the end
- Grace period defaults to two days instead of seven on new installs. An existing setting is left alone
- The Locked out text now explains why SSH still works, gives the exact command, and separates USB boot from internal boot
- The syslog line says which credential was used, `app code` or `backup code` with how many are left

### Fixed
- MFA is enabled but nothing to look at: the notice promised a dry run even when the server went straight to enforcing
- `aegis-mfa status` reported no enrolled accounts on a server that had them
- A half-finished code re-issue reappeared after a full uninstall, offering codes for an account that no longer existed
- Background requests received the login page instead of an answer, which showed up as stray text at the top of the webGUI
- On the white and azure themes the title, the notice and the summary cards could turn invisible
- Downloaded packages piled up on the boot device, one per release
- The stylesheet could stay cached after an update

## Version 2026.07.25

### Improvements
- The shield icon is drawn as a thin outline with a filled keyhole, in the header, on the settings page, in the Plugins list and in the CA artwork, which stays blue
- White and azure get darker overrides for the warning, locked, power, apply and link colours that were hard to read on light backgrounds

## Version 2026.07.24

### Improvements
- Wording changes for clearer phrasing

## Version 2026.07.21

### Fixed
- Support links now point to GitHub Issues, and the README wording was tightened

## Version 2026.07.19

### First release
- TOTP two-factor authentication for the Unraid webGUI, on top of the existing password login
- Any authenticator app works: Google Authenticator, Authy, Bitwarden, whatever you already use
- Root only: root is the only account the Unraid webGUI accepts, and enrols with its own secret and its own backup codes
- Setup wizard: scan a QR, confirm a code, save ten backup codes and type one back to finish
- The QR is generated on the server, the secret never leaves the machine
- Ten single-use backup codes, hashed on disk, with a remaining count in the settings
- Trusted LAN: no code prompt from networks you list, the password is still required. Your own address is shown ready to add
- Grace period: root gets a set number of days to enrol before setup becomes mandatory
- Dry-run: for the first 24 hours nothing is blocked, you see the prompts and failures are only logged, then you enforce when ready
- Lockout: repeated wrong codes lock the source IP out. Counters live in RAM, so brute force never wears the flash drive
- A code that was already used is refused, even inside its own 30-second window
- A failed code shows the server's own time, the usual culprit when codes suddenly stop matching
- Admin actions on the settings page: one-time setup link, fresh backup codes, reset
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
