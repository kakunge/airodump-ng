#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include "radiotap.h"

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump wlan0\n");
}

int main(int argc, char* argv[]) {
    uint8_t BSSID[6];
    int8_t PWR;
    int16_t Beacons;
    int16_t Data;
    int16_t CH;
    int16_t MB;
    char* ENC;
    char* CIPHER;
    char* AUTH;
    char* ESSID;
    uint8_t STATION[6];
    // Rate;
    // Lost;
    // Frames;
    // Notes;
    // Probes;

	if (argc != 2) {
		usage();
		return -1;
	}

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    std::list<uint32_t> present;
    std::list<uint32_t>::iterator iter;
    uint32_t* tempPresent;
    int numberOfPresent;




    while (true) {
        printf("\n");

        present.clear();
        iter = present.begin();
        numberOfPresent = 1;

		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        
		struct Radiotap* radiotap = (struct Radiotap*)packet;

        // printf("ver : %d\n", radiotap->version);
        // printf("pad : %d\n", radiotap->pad);
        // printf("len : %d\n", radiotap->len);

        do {
            tempPresent = (uint32_t*)(packet + 4 * numberOfPresent);
            present.push_back(*tempPresent);
            numberOfPresent++;

            // printf("---\n%d : %08x\n", numberOfPresent, *tempPresent);
            // printf("%08x\n---\n", *++iter);
        }
        while ((*tempPresent & 0x80000000) == 0x80000000);

        struct Dot11Frame* dot11Frame = (struct Dot11Frame*)(packet + radiotap->len);
        printf("type : %02x\n", dot11Frame->type);
        printf("flag : %02x\n", dot11Frame->flag);

        switch (dot11Frame->type) {
            case 0x08:
                printf("Data\n");
                break;
            case 0x24:
                printf("Trigger\n");
                break;
            case 0x40:
                printf("Probe Request\n");
                break;
            case 0x48:
                printf("Null fucntion\n");
                break;
            case 0x50:
                printf("Probe Response\n");
                break;
            case 0x54:
                printf("\n");
                break;
            case 0x80: {
                printf("Beacon frame\n");
                struct BeaconFrame* beaconFrame = (struct BeaconFrame*)(packet + radiotap->len);
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n", beaconFrame->BSSID[0], beaconFrame->BSSID[1], beaconFrame->BSSID[2], beaconFrame->BSSID[3], beaconFrame->BSSID[4], beaconFrame->BSSID[5]);
                // printf("SSID len : %d\nSSID : ", beaconFrame->ssidParameter.len);
                for (int i = 0; i < beaconFrame->ssidParameter.len; i++) {
                    printf("%c", beaconFrame->ssidParameter.SSID[i]);
                }
                printf("\n");
                break;
            }
            case 0x84:
                printf("Block Ack Req\n");
                break;
            case 0x94:
                printf("Block Ack\n");
                break;
            case 0xb4:
                printf("Request to send\n");
                break;
            case 0xc4:
                printf("Clear to send\n");
                break;
            case 0xd4:
                printf("Acknowledgement\n");
                break;
            case 0xe4:
                printf("CF-End\n");
                break;
            default:
                break;
        }



	}

	pcap_close(pcap);
}