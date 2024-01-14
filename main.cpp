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
#include <map>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include "radiotap.h"

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump wlan0\n");
}

int main(int argc, char* argv[]) {
    char BSSID[12];
    std::string keyBSSID;
    int8_t PWR;
    // int16_t Beacons;
    std::map<std::string, int> Beacons;
    int16_t Data;
    int16_t CH;
    int16_t MB;
    char* ENC;
    char* CIPHER;
    char* AUTH;
    char ESSID[32];
    std::string keyESSID;
    uint8_t STATION[6];
    // Rate;
    // Lost;
    // Frames;
    // Notes;
    // Probes;
    
    std::map<std::string, PackerInfo> APs;

	if (argc != 2) {
		usage();
		return -1;
	}

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	// pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    pcap_t* pcap = pcap_open_offline("wlan0.pcap", errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    std::list<uint32_t> present;
    std::list<uint32_t>::iterator iter;
    uint32_t* tempPresent;
    int numberOfPresent;

    while (true) {
        printf("\033[2J\033[H");


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
                // printBSSID(beaconFrame->BSSID);
                sprintf((char*)BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", beaconFrame->BSSID[0], beaconFrame->BSSID[1], beaconFrame->BSSID[2], beaconFrame->BSSID[3], beaconFrame->BSSID[4], beaconFrame->BSSID[5]);
                printf("BSSID : %s\n", BSSID);
                
                for (int i = 0; i < beaconFrame->ssidParameter.len; i++) {
                    ESSID[i] = beaconFrame->ssidParameter.SSID[i];
                }
                ESSID[beaconFrame->ssidParameter.len] = '\0';
                printf("ESSID : %s\n", ESSID);

                keyESSID = ESSID;
                keyBSSID = BSSID;
                auto it = Beacons.find(keyBSSID);

                if (it != Beacons.end()) {
                    it->second += 1;
                } else {
                    Beacons[keyBSSID] = 1;
                }

                // PackerInfo tempPacket = {*BSSID, Beacons[keyESSID], *ESSID};
                // APs[tempPacket.ESSID] = tempPacket;
                // printf("%s %d %s\n", tempPacket.BSSID, tempPacket.Beacons, tempPacket.ESSID);
                // std::memcpy(&APs[])

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

        // sleep(0.1);
        // system("clear");

        // printf("Beacons : %s %d\n", ESSID, Beacons[ESSID]);
        printf("Beacons\n");
        for (const auto& pair : Beacons) {
            printf("%s %d\n", pair.first.c_str(), pair.second);
        }
	}

        printf("Beacons\n");
        for (const auto& pair : Beacons) {
            printf("%s %d\n", pair.first.c_str(), pair.second);
        }

        printf("APs\n");
        for (const auto& pair : APs) {
            printf("%s %d\n", pair.first.c_str(), pair.second.Beacons);
            // printBSSID(pair.second->BSSID);
        }
	pcap_close(pcap);
}