/**
 * Code applied from:
 * - libnl sources LGPL2.1 https://www.infradead.org/~tgr/libnl/
 * - example code from Python libnl port (LGPL2.1):
 *   https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c
 * - as well as iw(8) source code (MIT).
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * This program uses the scanning features of wifi hardware to discover nearby
 * wifi access points and prints information about them. Due to libnl / nl80211
 * being used, this program only works on somewhat newer wifi drivers.
 * Only root can perform scanning due to NL80211_CMD_TRIGGER_SCAN being limited
 * to root by default.
 *
 * This changed version of the example program scan_access_points.c addresses several
 * errors that were not handled, scans for more information, rearranges the code
 * in a cleaner format and improves on the documentation. In addition, several memory
 * leaks with allocated libnl resources are handled.
 */

#include <errno.h>
#include <ctype.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <memory>
#include <stdio.h>

#define ARRAY_SIZE(ar) (sizeof(ar)/sizeof(ar[0]))

static unsigned char ms_oui[3]      = { 0x00, 0x50, 0xf2 };
static unsigned char ieee80211_oui[3]   = { 0x00, 0x0f, 0xac };
static unsigned char wfa_oui[3]     = { 0x50, 0x6f, 0x9a };

struct init_scan_results {
	int done;
	int aborted;
};

struct print_ies_data {
    unsigned char *ie;
    int ielen;
};

int error_handler(struct sockaddr_nl* nla, struct nlmsgerr* err, void* arg) {
	printf("error_handler() called\n");
	int* ret = (int*)arg;
	*ret = err->error;
	return NL_STOP;
}

// Callback for NL_CB_FINISH
int finish_handler(struct nl_msg* msg, void* arg) {
	int* ret = (int*)arg;
	*ret = 0;
	return NL_SKIP;
}

// Callback for NL_CB_ACK
int ack_handler(struct nl_msg *msg, void* arg) {
	int* ret = (int*)arg;
	*ret = 0;
	return NL_STOP;
}

// Callback for NL_CB_SEQ_CHECK
int no_seq_check(struct nl_msg* msg, void* arg) {
	return NL_OK;
}

// From http://git.kernel.org/cgit/linux/kernel/git/jberg/iw.git/tree/util.c
void mac_addr_n2a(char* mac_addr, unsigned char* arg) {

	int i, l;
	l = 0;
	for (i = 0; i < 6; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

void print_ssid_escaped(const uint8_t len, const uint8_t *data)
{
    int i;

    for (i = 0; i < len; i++) {
        if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
            printf("%c", data[i]);
        else if (data[i] == ' ' &&
             (i != 0 && i != len -1))
            printf(" ");
        else
            printf("\\x%.2x", data[i]);
    }
}

static void print_ssid(const uint8_t type, uint8_t len, const uint8_t *data,
               const struct print_ies_data *ie_buffer)
{
    printf(" ");
    print_ssid_escaped(len, data);
    printf("\n");
}


static void print_auth(const uint8_t *data)
{
	if (memcmp(data, ms_oui, 3) == 0) {
		switch (data[3]) {
		case 1:
			printf("IEEE 802.1X");
			break;
		case 2:
			printf("PSK");
			break;
		default:
			printf("%.02x-%.02x-%.02x:%d",
				data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else if (memcmp(data, ieee80211_oui, 3) == 0) {
		switch (data[3]) {
		case 1:
			printf("IEEE 802.1X");
			break;
		case 2:
			printf("PSK");
			break;
		case 3:
			printf("FT/IEEE 802.1X");
			break;
		case 4:
			printf("FT/PSK");
			break;
		case 5:
			printf("IEEE 802.1X/SHA-256");
			break;
		case 6:
			printf("PSK/SHA-256");
			break;
		case 7:
			printf("TDLS/TPK");
			break;
		case 8:
			printf("SAE");
			break;
		case 9:
			printf("FT/SAE");
			break;
		case 11:
			printf("IEEE 802.1X/SUITE-B");
			break;
		case 12:
			printf("IEEE 802.1X/SUITE-B-192");
			break;
		case 13:
			printf("FT/IEEE 802.1X/SHA-384");
			break;
		case 14:
			printf("FILS/SHA-256");
			break;
		case 15:
			printf("FILS/SHA-384");
			break;
		case 16:
			printf("FT/FILS/SHA-256");
			break;
		case 17:
			printf("FT/FILS/SHA-384");
			break;
		case 18:
			printf("OWE");
			break;
		default:
			printf("%.02x-%.02x-%.02x:%d",
				data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else if (memcmp(data, wfa_oui, 3) == 0) {
		switch (data[3]) {
		case 1:
			printf("OSEN");
			break;
		case 2:
			printf("DPP");
			break;
		default:
			printf("%.02x-%.02x-%.02x:%d",
				data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else
		printf("%.02x-%.02x-%.02x:%d",
			data[0], data[1] ,data[2], data[3]);
}

static void print_cipher(const uint8_t *data)
{
	if (memcmp(data, ms_oui, 3) == 0) {
		switch (data[3]) {
		case 0:
			printf("Use group cipher suite");
			break;
		case 1:
			printf("WEP-40");
			break;
		case 2:
			printf("TKIP");
			break;
		case 4:
			printf("CCMP");
			break;
		case 5:
			printf("WEP-104");
			break;
		default:
			printf("%.02x-%.02x-%.02x:%d",
				data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else if (memcmp(data, ieee80211_oui, 3) == 0) {
		switch (data[3]) {
		case 0:
			printf("Use group cipher suite");
			break;
		case 1:
			printf("WEP-40");
			break;
		case 2:
			printf("TKIP");
			break;
		case 4:
			printf("CCMP");
			break;
		case 5:
			printf("WEP-104");
			break;
		case 6:
			printf("AES-128-CMAC");
			break;
		case 7:
			printf("NO-GROUP");
			break;
		case 8:
			printf("GCMP");
			break;
		default:
			printf("%.02x-%.02x-%.02x:%d",
				data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else
		printf("%.02x-%.02x-%.02x:%d",
			data[0], data[1] ,data[2], data[3]);
}

static void _print_rsn_ie(const char *defcipher, const char *defauth,
			  uint8_t len, const uint8_t *data, int is_osen)
{
	bool first = true;
	__u16 count, capa;
	int i;

	if (!is_osen) {
		__u16 version;
		version = data[0] + (data[1] << 8);
		printf("\t * Version: %d\n", version);

		data += 2;
		len -= 2;
	}

	if (len < 4) {
		printf("\t * Group cipher: %s\n", defcipher);
		printf("\t * Pairwise ciphers: %s\n", defcipher);
		return;
	}

	printf("\t * Group cipher: ");
	print_cipher(data);
	printf("\n");

	data += 4;
	len -= 4;

	if (len < 2) {
		printf("\t * Pairwise ciphers: %s\n", defcipher);
		return;
	}

	count = data[0] | (data[1] << 8);
	if (2 + (count * 4) > len)
		goto invalid;

	printf("\t * Pairwise ciphers:");
	for (i = 0; i < count; i++) {
		printf(" ");
		print_cipher(data + 2 + (i * 4));
	}
	printf("\n");

	data += 2 + (count * 4);
	len -= 2 + (count * 4);

	if (len < 2) {
		printf("\t * Authentication suites: %s\n", defauth);
		return;
	}

	count = data[0] | (data[1] << 8);
	if (2 + (count * 4) > len)
		goto invalid;

	printf("\t * Authentication suites:");
	for (i = 0; i < count; i++) {
		printf(" ");
		print_auth(data + 2 + (i * 4));
	}
	printf("\n");

	data += 2 + (count * 4);
	len -= 2 + (count * 4);

	if (len >= 2) {
		capa = data[0] | (data[1] << 8);
		printf("\t * Capabilities:");
		if (capa & 0x0001)
			printf(" PreAuth");
		if (capa & 0x0002)
			printf(" NoPairwise");
		switch ((capa & 0x000c) >> 2) {
		case 0:
			printf(" 1-PTKSA-RC");
			break;
		case 1:
			printf(" 2-PTKSA-RC");
			break;
		case 2:
			printf(" 4-PTKSA-RC");
			break;
		case 3:
			printf(" 16-PTKSA-RC");
			break;
		}
		switch ((capa & 0x0030) >> 4) {
		case 0:
			printf(" 1-GTKSA-RC");
			break;
		case 1:
			printf(" 2-GTKSA-RC");
			break;
		case 2:
			printf(" 4-GTKSA-RC");
			break;
		case 3:
			printf(" 16-GTKSA-RC");
			break;
		}
		if (capa & 0x0040)
			printf(" MFP-required");
		if (capa & 0x0080)
			printf(" MFP-capable");
		if (capa & 0x0200)
			printf(" Peerkey-enabled");
		if (capa & 0x0400)
			printf(" SPP-AMSDU-capable");
		if (capa & 0x0800)
			printf(" SPP-AMSDU-required");
		if (capa & 0x2000)
			printf(" Extended-Key-ID");
		printf(" (0x%.4x)\n", capa);
		data += 2;
		len -= 2;
	}

	if (len >= 2) {
		int pmkid_count = data[0] | (data[1] << 8);

		if (len >= 2 + 16 * pmkid_count) {
			printf("\t * %d PMKIDs\n", pmkid_count);
			/* not printing PMKID values */
			data += 2 + 16 * pmkid_count;
			len -= 2 + 16 * pmkid_count;
		} else
			goto invalid;
	}

	if (len >= 4) {
		printf("\t * Group mgmt cipher suite: ");
		print_cipher(data);
		printf("\n");
		data += 4;
		len -= 4;
	}

 invalid:
	if (len != 0) {
		printf("\t\t * bogus tail data (%d):", len);
		while (len) {
			printf(" %.2x", *data);
			data++;
			len--;
		}
		printf("\n");
	}
}

static void print_rsn_ie(const char *defcipher, const char *defauth, uint8_t len, const uint8_t *data)
{
    _print_rsn_ie(defcipher, defauth, len, data, 0);
}

static void print_rsn(const uint8_t type, uint8_t len, const uint8_t *data, const struct print_ies_data *ie_buffer)
{
    print_rsn_ie("CCMP", "IEEE 802.1X", len, data);
	return;
}

struct ie_print {
    const char *name;
    void (*print)(const uint8_t type, uint8_t len, const uint8_t *data,
		const struct print_ies_data *ie_buffer);
    uint8_t minlen;
	uint8_t maxlen;
};

struct ie_print ieprinters[100];

static void print_ie(const struct ie_print *p, const uint8_t type, uint8_t len,
	const uint8_t *data, const struct print_ies_data *ie_buffer) {

    int i;

    if (!p->print)
        return;

    printf("\t%s:", p->name);
    if (len < p->minlen || len > p->maxlen) {
        if (len > 1) {
            printf(" <invalid: %d bytes:", len);
            for (i = 0; i < len; i++)
                printf(" %.02x", data[i]);
            printf(">\n");
        } else if (len)
            printf(" <invalid: 1 byte: %.02x>\n", data[0]);
        else
            printf(" <invalid: no data>\n");
        return;
    }

    p->print(type, len, data, ie_buffer);
}

#if 0
void print_ies(unsigned char* ie, int ielen) {

	uint8_t len;
	uint8_t* data;
	int i;

	printf(" ");
    //[0] = { "SSID", print_ssid, 0, 32, BIT(PRINT_SCAN) | BIT(PRINT_LINK), },
    //[48] = { "RSN", print_rsn, 2, 255, BIT(PRINT_SCAN), },

	while (ielen >= 2 && ielen >= ie[1]) {

		if (ie[0] == 0 && ie[1] >= 0 && ie[1] <= 32) {

			len = ie[1];
			data = ie + 2;

			for (i = 0; i < len; i++) {

				if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\') {
					printf("%c", data[i]);
				} else if (data[i] == ' ' && (i != 0 && i != len -1)) {
					printf(" ");
				} else {
					printf("\\x%.2x", data[i]);
				}
			}

			break;
        } else if (ie[0] == 48 && ie[1] >= 2 && ie[1] <= 255) {
            printf("got ie type 48\n");
        }

		ielen -= ie[1] + 2;
		ie += ie[1] + 2;
	}
}
#endif

void print_ies(unsigned char *ie, int ielen) {

    struct print_ies_data ie_buffer = {
        .ie = ie,
        .ielen = ielen
	};

    if (ie == NULL || ielen < 0)
        return;

    while (ielen >= 2 && ielen - 2 >= ie[1]) {
        if (ie[0] < ARRAY_SIZE(ieprinters) && ieprinters[ie[0]].name) {
            print_ie(&ieprinters[ie[0]], ie[0], ie[1], ie + 2, &ie_buffer);
        }
        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
    }
}

// Called by the kernel when the scan is done or has been aborted.
int valid_data_cb(struct nl_msg* msg, void* arg) {

	struct genlmsghdr* gnlh = (genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
	struct init_scan_results* results = (init_scan_results*)arg;

	if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
		printf("Got NL80211_CMD_SCAN_ABORTED.\n");
		results->done = 1;
		results->aborted = 1;
    } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
        printf("Got NL80211_CMD_NEW_SCAN_RESULTS.\n");
        results->done = 1;
        results->aborted = 0;
    }
	// else probably an uninteresting multicast message.

	return NL_SKIP;
}


// Called by the kernel with a dump of the successful scan's data. Called for each SSID.
int receive_scan_result(struct nl_msg *msg, void *arg) {

	struct genlmsghdr* gnlh = (genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
	char mac_addr[20];

	struct nlattr* tb[NL80211_ATTR_MAX + 1];
	struct nlattr* bss[NL80211_BSS_MAX + 1];
	struct nla_policy bss_policy[NL80211_BSS_MAX + 1];

	memset(bss_policy, 0, sizeof(bss_policy));
	memset(bss, 0, sizeof(bss));
	memset(tb, 0, sizeof(tb));

	bss_policy[NL80211_BSS_TSF] = { .type = NLA_U64 };
	bss_policy[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
	bss_policy[NL80211_BSS_BSSID] = { };
	bss_policy[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 };
	bss_policy[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 };
	bss_policy[NL80211_BSS_INFORMATION_ELEMENTS] = { };
	bss_policy[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 };
	bss_policy[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 };
	bss_policy[NL80211_BSS_STATUS] = { .type = NLA_U32 };
	bss_policy[NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 };
	bss_policy[NL80211_BSS_BEACON_IES] = { };

//	struct nla_policy my_policy[MY_ATTR_MAX+1];
//	my_policy[NL80211_ATTR_AUTH_TYPE] = { .type = NLA_U32 };

/*
enum nl80211_auth_type {
	NL80211_AUTHTYPE_OPEN_SYSTEM,
	NL80211_AUTHTYPE_SHARED_KEY,
	NL80211_AUTHTYPE_FT,
	NL80211_AUTHTYPE_NETWORK_EAP,
	NL80211_AUTHTYPE_SAE,
	NL80211_AUTHTYPE_FILS_SK,
	NL80211_AUTHTYPE_FILS_SK_PFS,
	NL80211_AUTHTYPE_FILS_PK,

	__NL80211_AUTHTYPE_NUM,
	NL80211_AUTHTYPE_MAX = __NL80211_AUTHTYPE_NUM - 1,
	NL80211_AUTHTYPE_AUTOMATIC
};

enum nl80211_wpa_versions {
	NL80211_WPA_VERSION_1 = 1 << 0,
	NL80211_WPA_VERSION_2 = 1 << 1,
	NL80211_WPA_VERSION_3 = 1 << 2,
};
*/

//NL80211_ATTR_AUTH_TYPE

	int err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	if (err < 0) {
		printf("error creating attribute indices from scan message: %d, %s\n", err, nl_geterror(err));
		return NL_SKIP;
	}

	if (!tb[NL80211_ATTR_BSS]) {
		printf("bss info missing\n");
		return NL_SKIP;
	}

	err = nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy);
	if (err < 0) {
		printf("failed to parse nested attributes: %d, %s\n", err, nl_geterror(err));
		return NL_SKIP;
	}

	if (!bss[NL80211_BSS_BSSID]) {
		return NL_SKIP;
	}

	if (!bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
		return NL_SKIP;
	}

	mac_addr_n2a(mac_addr, (unsigned char*)nla_data(bss[NL80211_BSS_BSSID]));

	printf(" %s", mac_addr);
	if (bss[NL80211_BSS_SIGNAL_MBM]) {
		printf(" signal strength: %d", nla_get_u8(bss[NL80211_BSS_SIGNAL_MBM]));
	} else if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
		printf(" signal strength: %d", nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]));
	}
	if (bss[NL80211_BSS_FREQUENCY]) {
		printf(" %d MHz", nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
	}

	//print_ies((unsigned char*)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]), nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));
	//printf("\n");

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {

        struct nlattr* ies = bss[NL80211_BSS_INFORMATION_ELEMENTS];
        struct nlattr* bcnies = bss[NL80211_BSS_BEACON_IES];

        if (bss[NL80211_BSS_PRESP_DATA] || (bcnies && (nla_len(ies) != nla_len(bcnies) ||
			memcmp(nla_data(ies), nla_data(bcnies), nla_len(ies))))) {
		}

        print_ies((unsigned char*)nla_data(ies), nla_len(ies));
    }

	if (bss[NL80211_BSS_BEACON_IES]) {
		print_ies((unsigned char*)nla_data(bss[NL80211_BSS_BEACON_IES]), nla_len(bss[NL80211_BSS_BEACON_IES]));
	}

	return NL_SKIP;
}

int do_scan_trigger(struct nl_sock* socket, int if_index, int family_id) {

	// Starts the scan and waits for it to finish.
	// Does not return until the scan is done or has been aborted.

	struct init_scan_results results = { .done = 0, .aborted = 0 };
	struct nl_msg* msg = NULL;
	struct nl_msg* ssids_to_scan = NULL;
	struct nl_cb* cb = NULL;
	int err;
	int ret;
	int mcid = -1;

	std::shared_ptr<void> defer(nullptr, [&](...){
		if (ssids_to_scan != NULL) {
			nlmsg_free(ssids_to_scan);
		}

		if (msg != NULL) {
			nlmsg_free(msg);
		}

		if (cb != NULL) {
			nl_cb_put(cb);
		}

		if (mcid >= 0) {
			nl_socket_drop_membership(socket, mcid);
		}
	});

	mcid = genl_ctrl_resolve_grp(socket, "nl80211", "scan");

	if (mcid < 0) {
		printf("error resolving netlink group name to identifier: %d, %s\n",
			mcid, nl_geterror(err));
		return 1;
	}

	// join the netlink socket into the scan group resolved above
	err = nl_socket_add_membership(socket, mcid);
	if (err < 0) {
		printf("error joining scan group: %d, %s\n", err, nl_geterror(err));
		return 1;
	}

	// Allocate netlink messages with the default size
	msg = nlmsg_alloc();
	ssids_to_scan = nlmsg_alloc();

	if (msg == NULL || ssids_to_scan == NULL) {
		printf("Failed allocating netlink message\n");
		return 1;
	}

	// allocate a callback handle with default quiet callback type
	cb = nl_cb_alloc(NL_CB_DEFAULT);

	if (!cb) {
		printf("Failed allocating callback\n");
		return 1;
	}

	// Setup the messages and callback handler.

	// Construct message header
	// I think this function returns something relevant only if the user_header parameter
	// is specified as non-zero? I have no idea.
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);

	// Add message attribute specifying which interface to use.
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

	// Scan all SSIDs
	// TODO: what are these values?
	nla_put(ssids_to_scan, 1, 0, "");

	// Add message attribute specifiying which SSIDs to scan for
	nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan);

	// Copied to msg above, no longer need this
	nlmsg_free(ssids_to_scan);
	ssids_to_scan = NULL;

	// Add callbacks - apparently the same callback handle is used for all of them?
	ret = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_data_cb, &results);
	if (ret < 0) {
		printf("Failed setting NL_CB_VALID callback: %d, %s\n", ret, nl_geterror(ret));
		return 1;
	}

	ret = nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	if (ret < 0) {
		printf("Failed setting NL_CB_CUSTOM callback: %d, %s\n", ret, nl_geterror(ret));;
		return 1;
	}

	ret = nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	if (ret < 0) {
		printf("Failed setting NL_CB_FINISH callback: %d, %s\n", ret, nl_geterror(ret));
		return 1;
	}

	int ack_got = 0;
	ret = nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ack_got);
	if (ret < 0) {
		printf("Failed setting NL_CB_ACK callback: %d, %s\n", ret, nl_geterror(ret));
		return 1;
	}

	// No sequence checking for multicast messages
	ret = nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	if (ret < 0) {
		printf("Failed setting NL_CB_ACK callback: %d, %s\n", ret, nl_geterror(ret));
		return 1;
	}

	// reset error flag
	err = 1;

	// Send NL80211_CMD_TRIGGER_SCAN to start the scan.
	// The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on success or
	// NL80211_CMD_SCAN_ABORTED if another scan was started by another process.

	int written = nl_send_auto(socket, msg);
	if (written < 0) {
		printf("error in nl_send_auto: %d, %s\n", written, nl_geterror(written));
		return 1;
	}

	printf("nl_send_auto wrote %d bytes\n", written);
	printf("Waiting for scan to complete\n");

	// wait for NL_CB_ACK
	while (ack_got != 0) {
		ret = nl_recvmsgs(socket, cb);
		if (ret < 0) {
			printf("nl_recvmsgs returned error: %d, %s\n", ret, nl_geterror(ret));
			return 1;
		}
	}

	if (err < 0) {
		printf("error flag set during message transmission: %d, %s\n", err, nl_geterror(err));
		return 1;
	}

	while (results.done != 1) {
		// Now wait until the scan is done or aborted
		nl_recvmsgs(socket, cb);
	}

	if (results.aborted == 1) {
		printf("scan was aborted\n");
		return 1;
	}

	printf("Scan is done\n");
	return 0;
}

int main(int argc, char** argv) {

	if (argc < 2) {
		printf("usage: programname wifi_adapter_name\nie: ./programname wlp2s0.\n");
		return 1;
	}

	memset(ieprinters, 0, sizeof(ieprinters));
	ieprinters[0] = { "SSID", print_ssid, 0, 32 };
	ieprinters[48] = { "RSN", print_rsn, 2, 255, };

	const char* ifname = argv[1];
	printf("Using interface: %s\n", ifname);

	int if_index = if_nametoindex(ifname);
	if (if_index == 0) {
		printf("error matching interface %s into a real interface: %d, %s\n",
			ifname, errno, strerror(errno));
		return 1;
	}

	// Allocate a netlink socket
	struct nl_sock* nlsocket = nl_socket_alloc();
	if (nlsocket == NULL) {
		printf("Failed allocating nl socket\n");
		return 1;
	}

	struct nl_msg* msg = NULL;

	std::shared_ptr<void> defer(nullptr, [&](...){
		if (nlsocket) {
			nl_socket_free(nlsocket);
			nlsocket = NULL;
		}

		if (msg) {
			nlmsg_free(msg);
		}
	});

	// Connect the allocated socket to libnl
	int err = genl_connect(nlsocket);
	if (err < 0) {
		printf("Error connecting nl socket: %d, %s\n", err, nl_geterror(err));
		return 1;
	}

	// Match the nl80211 netlink family name to its identifier
	int family_id = genl_ctrl_resolve(nlsocket, "nl80211");
	if (family_id  < 0) {
		printf("error finding identifier for nl80211 family name: %d, %s\n",
			family_id, nl_geterror(family_id));
		return 1;
	}

	// Issue NL80211_CMD_TRIGGER_SCAN to the kernel and wait for it to finish
	err = do_scan_trigger(nlsocket, if_index, family_id);

	if (err != 0) {
		printf("do_scan_trigger() failed with %d\n", err);
		return 1;
	}

	// get info for all SSIDs detected

	// Allocate a message
	msg = nlmsg_alloc();

	// Setup which command to run
	genlmsg_put(msg, 0, 0, family_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);

	// Add message attribute specifying which interface to use.
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

	// Add callback for getting data
	nl_socket_modify_cb(nlsocket, NL_CB_VALID, NL_CB_CUSTOM, receive_scan_result, NULL);

	// Send the message
	int ret = nl_send_auto(nlsocket, msg);

	printf("NL80211_CMD_GET_SCAN sent %d bytes.\n", ret);

	// wait for the message to go through
	ret = nl_recvmsgs_default(nlsocket);

	if (ret < 0) {
		printf("ERROR: nl_recvmsgs_default() returned %d (%s).\n", ret, nl_geterror(-ret));
		return ret;
	}

	return 0;
}

