# libnl based wifi access point scanner

This program uses the scanning features of wifi hardware to discover nearby wifi access points and prints information about them. Due to libnl / nl80211 being used, this program only works on somewhat newer wifi drivers. Only root can perform scanning due to `NL80211_CMD_TRIGGER_SCAN` being limited to root by default.

The is code is applied from:

* libnl sources: [https://www.infradead.org/~tgr/libnl/](https://www.infradead.org/~tgr/libnl/])
* example code from Python libnl port: [https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c](https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c)

This changed version of the example program `scan_access_points.c` addresses several errors that were not handled, scans for more information, rearranges the code in a cleaner format and improves on the documentation. In addition, several memory leaks with allocated libnl resources are handled.

This program is Linux only.

### Dependencies

* libnl. On Debian, install: `libnl-3-dev libnl-genl-3-dev`

### Building

* `make`

