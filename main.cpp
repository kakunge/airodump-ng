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
#include <ctime>
#include "radiotap.h"

void usage() {
	printf("syntax : airodump <option> <interface>\n");
	printf("sample : airodump --on wlan0\n\n");
    printf("options\n");
    printf("  --on <interface> : use pcap_open_live function\n");
    printf("  --off <filename> : use pcap_open_offline function\n");
}

int main(int argc, char* argv[]) {
    std::time_t startTime = std::time(nullptr);
    std::time_t endTime;
    std::time_t curTime = endTime - startTime;

    char BSSID[12];
    std::string stringBSSID;
    int8_t PWR;
    std::map<std::string, int8_t> PWRs;
    std::map<std::string, int> Beacons;
    int16_t Data;
    int16_t CH;
    int16_t MB;
    char* ENC;
    char* CIPHER;
    char* AUTH;
    char ESSID[32];
    std::string stringESSID;
    std::map<std::string, std::string> ESSIDs;

    char STATION[12];
    std::string stringSTATION;
    std::map<std::string, std::string> STATIONs;

	if (argc != 3) {
		usage();
		return -1;
	}

    char* mode = argv[1];
    char* dev = argv[2];
    pcap_t* pcap;
	char errbuf[PCAP_ERRBUF_SIZE];

    if (!strcmp(mode, "--on")) {
        pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    }
    else if (!strcmp(mode, "--off")) {
        pcap = pcap_open_offline(dev, errbuf);
    }
    else {
        usage();
    }
	// pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    // pcap_t* pcap = pcap_open_offline("wlan0.pcap", errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    printf("\033[2J");

    std::list<uint32_t> present;
    std::list<uint32_t>::iterator iter;
    uint32_t* tempPresent;
    int numberOfPresent;

    while (true) {
        endTime = std::time(nullptr);
        printf("\033[H");
        printf("[ Elapsed %ds ]\n\n", endTime - startTime);
        printf("%s%24s%12s\t%s\n\n", "BSSID", "Beacons", "PWR", "ESSID");


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
        // printf("type : %02x\n", dot11Frame->type);
        // printf("flag : %02x\n", dot11Frame->flag);

        switch (dot11Frame->type) {
            case 0x08:
                // printf("Data\n");
                break;
            case 0x24:
                // printf("Trigger\n");
                break;
            case 0x40:
                // printf("Probe Request\n");
                break;
            case 0x48:
                // printf("Null fucntion\n");
                break;
            case 0x50:
                // printf("Probe Response\n");
                break;
            case 0x54:
                printf("\n");
                break;
            case 0x80: {
                printf("Beacon frame\n");
                printf("PWR : %d\n", radiotap->anteSig);
                struct BeaconFrame* beaconFrame = (struct BeaconFrame*)(packet + radiotap->len);
                // printBSSID(beaconFrame->BSSID);
                sprintf((char*)BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", beaconFrame->BSSID[0], beaconFrame->BSSID[1], beaconFrame->BSSID[2], beaconFrame->BSSID[3], beaconFrame->BSSID[4], beaconFrame->BSSID[5]);
                // printf("BSSID : %s\n", BSSID);

                // ------

                struct TaggedParameter* taggedParameter;
                taggedParameter = (struct TaggedParameter*)(packet + radiotap->len + 36);

                printf("num : 0x%02x\n", taggedParameter->tagNumber);

                if (taggedParameter->tagNumber == 0x00) {
                    printf("SSID\n");
                    for (int i = 0; i < taggedParameter->len; i++) {
                        ESSID[i] = taggedParameter->data[i];
                    }
                    ESSID[taggedParameter->len] = '\0';
                }

                // ------
                
                // for (int i = 0; i < beaconFrame->ssidParameter.len; i++) {
                //     ESSID[i] = beaconFrame->ssidParameter.SSID[i];
                // }
                // ESSID[beaconFrame->ssidParameter.len] = '\0';
                // printf("ESSID : %s\n", ESSID);

                // ------

                stringBSSID = BSSID;
                stringESSID = ESSID;
                auto it = Beacons.find(stringBSSID);

                PWRs[stringBSSID] = radiotap->anteSig;

                if (it != Beacons.end()) {
                    it->second += 1;
                } else {
                    Beacons[stringBSSID] = 1;
                    ESSIDs[stringBSSID] = stringESSID;
                }

                break;
            }
            case 0x84:
                // printf("Block Ack Req\n");
                break;
            case 0x94:
                // printf("Block Ack\n");
                break;
            case 0xb4:
                // printf("Request to send\n");
                break;
            case 0xc4:
                // printf("Clear to send\n");
                break;
            case 0xd4:
                // printf("Acknowledgement\n");
                break;
            case 0xe4:
                // printf("CF-End\n");
                break;
            default:
                break;
        }
        // system("clear");

        // printf("Beacons : %s %d\n", ESSID, Beacons[ESSID]);

        // printf("Beacons\n");
        // for (const auto& pair : Beacons) {
        //     printf("%s %d\n", pair.first.c_str(), pair.second);
        // }

        // printf("Beacons\n");
        for (const auto& pair : Beacons) {
            printf("%s%12d%12d\t%-32s\n", pair.first.c_str(), pair.second, PWRs[pair.first], ESSIDs[pair.first].c_str());
        }

        sleep(0.1);
	}

        // printf("Beacons\n");
        for (const auto& pair : Beacons) {
            printf("%s%12d%12d\t%-32s\n", pair.first.c_str(), pair.second, PWRs[pair.first], ESSIDs[pair.first].c_str());
        }
	pcap_close(pcap);
}