# Widevine installer for aarch64 systems

This tool will download and install Widevine systemwide for aarch64 systems.
It performs the necessary configuration changes to make Widevine available for
both Firefox and Chromium-based browsers.

NOTE: Using Widevine requires glibc version 2.36 or later. Arch Linux ARM ships
an ancient glibc version, and will not work at this time. Most other distros
(even Debian stable) should be OK.

# Credits

Original fixup script by [@DavidBuchanan314](https://github.com/DavidBuchanan314):
https://gist.github.com/DavidBuchanan314/c6b97add51b97e4c3ee95dc890f9e3c8

Changes to support newer CDMs and vanilla glibc and install script by
[@marcan](https://github.com/marcan).
