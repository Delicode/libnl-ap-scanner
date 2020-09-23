# libnl based wifi access point scanner

This program uses the scanning features of wifi hardware to discover nearby wifi access points and prints information about them. Due to libnl / nl80211 being used, this program only works on somewhat newer wifi drivers. Only root can perform scanning due to `NL80211_CMD_TRIGGER_SCAN` being limited to root by default.

This changed version of the example program `scan_access_points.c` addresses several errors that were not handled, scans for more information, rearranges the code in a cleaner format and improves on the documentation. In addition, several memory leaks with allocated libnl resources are handled.

Due to libnl, this program is Linux only.

### Dependencies

* libnl. On Debian, install: `libnl-3-dev libnl-genl-3-dev`

### Building

* `make`

