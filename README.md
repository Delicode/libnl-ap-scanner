# libnl based wifi access point scanner

This program uses the scanning features of wifi hardware to discover nearby wifi access points and prints information about them. Due to libnl / nl80211 being used, this program only works on somewhat newer wifi drivers on Linux. Only root can perform scanning due to `NL80211_CMD_TRIGGER_SCAN` being limited to root by default.

The program is designed to for being parsed by other programs. iw(8), when executing, says:

```
Do NOT screenscrape this tool, we don't consider its output stable.
```

As such, there was a need for AP scanning tool that **does** have stable output. The program output is approximately following:

```
gekko@gekkoslovakia:~/libnl-ap-scanner$ make && sudo ./ap-scanner wlp2s0
make: Nothing to be done for 'all'.
Using interface: wlp2s0
nl_send_auto wrote 36 bytes
Waiting for scan to complete
Scan is done
AP_DISCOVERED:2c:56:dc:5c:8e:85
AP_DATA:2c:56:dc:5c:8e:85,signal strength:152
AP_DATA:2c:56:dc:5c:8e:85,frequency:2437 MHz
AP_DATA:2c:56:dc:5c:8e:85,ssid:Hannibal
AP_DATA:2c:56:dc:5c:8e:85,RSN version:1
AP_DATA:2c:56:dc:5c:8e:85,RSN group cipher:CCMP
AP_DATA:2c:56:dc:5c:8e:85,RSN pairwise ciphers:,CCMP
AP_DATA:2c:56:dc:5c:8e:85,RSN authentication suites: IEEE 802.1X
AP_DATA:2c:56:dc:5c:8e:85,RSN capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
AP_DATA:2c:56:dc:5c:8e:85,ssid:Hannibal
AP_DATA:2c:56:dc:5c:8e:85,RSN version:1
AP_DATA:2c:56:dc:5c:8e:85,RSN group cipher:CCMP
AP_DATA:2c:56:dc:5c:8e:85,RSN pairwise ciphers:,CCMP
AP_DATA:2c:56:dc:5c:8e:85,RSN authentication suites: IEEE 802.1X
AP_DATA:2c:56:dc:5c:8e:85,RSN capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)

AP_DISCOVERED:70:df:2f:9e:0f:40
AP_DATA:70:df:2f:9e:0f:40,signal strength:224
AP_DATA:70:df:2f:9e:0f:40,frequency:2412 MHz
AP_DATA:70:df:2f:9e:0f:40,ssid:aalto
AP_DATA:70:df:2f:9e:0f:40,RSN version:1
AP_DATA:70:df:2f:9e:0f:40,RSN group cipher:CCMP
AP_DATA:70:df:2f:9e:0f:40,RSN pairwise ciphers:,CCMP
AP_DATA:70:df:2f:9e:0f:40,RSN authentication suites: IEEE 802.1X
AP_DATA:70:df:2f:9e:0f:40,RSN capabilities: 4-PTKSA-RC 4-GTKSA-RC (0x0028)
AP_DATA:70:df:2f:9e:0f:40,ssid:aalto
AP_DATA:70:df:2f:9e:0f:40,RSN version:1
AP_DATA:70:df:2f:9e:0f:40,RSN group cipher:CCMP
AP_DATA:70:df:2f:9e:0f:40,RSN pairwise ciphers:,CCMP
AP_DATA:70:df:2f:9e:0f:40,RSN authentication suites: IEEE 802.1X
AP_DATA:70:df:2f:9e:0f:40,RSN capabilities: 4-PTKSA-RC 4-GTKSA-RC (0x0028)
```

Lines beginning with `AP_DISCOVER` and `AP_DATA` are intended for parsing.

### Dependencies

* libnl. On Debian, install: `libnl-3-dev libnl-genl-3-dev`

### Building

* `make`

### Code quality

When I started working on this tool, I had to start learning the WIFI protocol, the nl80211 header, netlink as well as undocumented code written by others. I did my best documenting the entire program, but there are areas that I don't understand and which are directly copied from iw source code. I'm open for contributions improving the documentation as well as handling potentially remaining memory leaks or bugs.

### Other developers

The is code is applied from:

* libnl sources: [https://www.infradead.org/~tgr/libnl/](https://www.infradead.org/~tgr/libnl/])
* example code from Python libnl port: [https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c](https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c)
* iw(8) source code: [https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git](https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git)

This changed version of the example program `scan_access_points.c` addresses several errors that were not handled, scans for more information, rearranges the code in a cleaner format and improves on the documentation. In addition, several memory leaks with allocated libnl resources are handled.

