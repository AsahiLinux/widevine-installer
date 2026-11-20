# Widevine installer for aarch64 systems

This tool will download and install Widevine systemwide for aarch64 systems.
It performs the necessary configuration changes to make Widevine available for
both Firefox and Chromium-based browsers.

The CDM is the official, unmodified Linux ARM64 build that Google distributes
to Chrome. It is fetched from Google's component update service, verified
against the SHA-256 returned by that service, and installed as-is. No binary
patching or special glibc is required.

Each run checks for the latest available CDM. If it is newer than the
installed one (or nothing is installed yet), it is downloaded and installed;
otherwise the script reports that Widevine is up to date and exits. Re-run
`widevine-installer` to update.

Runtime dependencies: `curl`, `python3` and `sha256sum` (coreutils).

# Credits

Component update service approach adapted from
[@mostman](https://github.com/mostman)'s Slackware build:
https://github.com/mostman/Slackbuilds/tree/Slackwareaarch64-current/widevine
(itself inspired by
[Kodi InputStream Helper](https://github.com/emilsvennesson/script.module.inputstreamhelper)).

Earlier versions of this tool adapted the ChromeOS CDM using a fixup script by
[@DavidBuchanan314](https://github.com/DavidBuchanan314), with changes and the
install script by [@marcan](https://github.com/marcan).
