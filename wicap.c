#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <string.h>
#include <pcap/pcap.h>
#include "radiotap_iter.h"

static int fcshdr = 0;

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

struct ieee80211_hdr {
	unsigned short frame_control;
	unsigned short duration_id;
	unsigned char addr1[6];
	unsigned char addr2[6];
	unsigned char addr3[6];
	unsigned short seq_ctrl;
	unsigned short addr4[6];
} __attribute__ ((packed));

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
		printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		printf("\tflags: %02x\n", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_RATE:
		printf("\trate: %lf\n", (double)*iter->this_arg/2);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		printf("\tchannel frequency: %d\n", (u_int16_t)*iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		printf("\tdbm antsignal: %d\n", (int8_t)*iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		printf("\tdbm antnoise: %d\n", (int8_t)*iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_ANTENNA:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		printf("\tdb antsignal: %d\n", (int8_t)*iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
		printf("\tdb antnoise: %d\n", (int8_t)*iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_TX_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
		if (fcshdr) {
			printf("\tFCS in header: %.8x\n",
				le32toh(*(uint32_t *)iter->this_arg));
			break;
		}
		printf("\tRX flags: %#.4x\n",
			le16toh(*(uint16_t *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
		break;
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}

static void print_test_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case 0:
	case 52:
		printf("\t00:00:00-00|%d: %.2x/%.2x/%.2x/%.2x\n",
			iter->this_arg_index,
			*iter->this_arg, *(iter->this_arg + 1),
			*(iter->this_arg + 2), *(iter->this_arg + 3));
		break;
	default:
		printf("\tBOGUS DATA - vendor ns %d\n", iter->this_arg_index);
		break;
	}
}

static const struct radiotap_override overrides[] = {
	{ .field = 14, .align = 4, .size = 4, }
};

int save_packet(const pcap_t *pcap_handle, const struct pcap_pkthdr *header, 
        const u_char *packet, const char *file_name)
{
	pcap_dumper_t *output_file;
	
    output_file = pcap_dump_open(pcap_handle, file_name);
    if (output_file == NULL) {
        printf("Fail to save captured packet.\n");
        return -1;
    }

    pcap_dump((u_char *)output_file, header, packet);
    pcap_dump_close(output_file);
    
    return 0;
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int err;
    int i;
	struct ieee80211_radiotap_iterator iter;
    char *save_file_name = "wicap_capture.pcap";

    printf("\nGot one packet:\n");

    save_packet((pcap_t *)args, header, packet, save_file_name);

    err = ieee80211_radiotap_iterator_init(&iter, packet, 2014, &vns);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return;
	}

    /**
     * Parsing captured data packet and print radiotap information.
     */
    while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
				iter.this_arg[0], iter.this_arg[1],
				iter.this_arg[2], iter.this_arg[3],
				iter.this_arg_size - 6);
			for (i = 6; i < iter.this_arg_size; i++) {
				if (i % 8 == 6)
					printf("\t\t");
				else
					printf(" ");
				printf("%.2x", iter.this_arg[i]);
			}
			printf("\n");
		} else if (iter.is_radiotap_ns)
			print_radiotap_namespace(&iter);
		else if (iter.current_namespace == &vns_array[0])
			print_test_namespace(&iter);
	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return;
	}

    struct ieee80211_hdr *hdr =(struct ieee80211_hdr *)(packet + iter._max_length);
    printf("\tsource address: "MACSTR"\n", MAC2STR(hdr->addr2));
    printf("\tdestination address: "MACSTR"\n", MAC2STR(hdr->addr1));
    printf("\tbssid: "MACSTR"\n", MAC2STR(hdr->addr3));

	return;

}

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    bpf_u_int32 netp;
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "type mgt subtype assoc-req";	/* The filter expression */
    int num_packets = 2;			/* number of packets to capture */

    /* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		return 1;
	}
    
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 100000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    
    /* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

    /* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, handle);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");    
    
    return(0);
}
