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
    // int8_t PWR;
    std::map<std::string, int8_t> PWRs;

    std::map<std::string, int> Beacons;
    // int16_t CH;
    std::map<std::string, int16_t> CHs;
    // int16_t MB;
    // char* ENC;
    // char* CIPHER;
    // char* AUTH;
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
        pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
        printf("%s%32s%12s%12s\t%s\n", "BSSID", "PWR", "Beacons", "CH", "ESSID");

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

        do {
            tempPresent = (uint32_t*)(packet + 4 * numberOfPresent);
            present.push_back(*tempPresent);
            numberOfPresent++;
        }
        while ((*tempPresent & 0x80000000) == 0x80000000);

        struct Dot11Frame* dot11Frame = (struct Dot11Frame*)(packet + radiotap->len);

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
            case 0x48: {
                // printf("Null fucntion\n");
                struct NullFunction* nullFunction = (struct NullFunction*)(packet + radiotap->len);
                sprintf((char*)BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", nullFunction->BSSID[0], nullFunction->BSSID[1], nullFunction->BSSID[2], nullFunction->BSSID[3], nullFunction->BSSID[4], nullFunction->BSSID[5]);
                stringBSSID = BSSID;
                sprintf((char*)STATION, "%02x:%02x:%02x:%02x:%02x:%02x", nullFunction->sourAddr[0], nullFunction->sourAddr[1], nullFunction->sourAddr[2], nullFunction->sourAddr[3], nullFunction->sourAddr[4], nullFunction->sourAddr[5]);
                stringSTATION = STATION;

                STATIONs[stringSTATION] = stringBSSID;

                break;
            }
            case 0x50:
                // printf("Probe Response\n");
                break;
            case 0x54:
                printf("\n");
                break;
            case 0x80: {
                // printf("Beacon frame\n");
                struct BeaconFrame* beaconFrame = (struct BeaconFrame*)(packet + radiotap->len);
                sprintf((char*)BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", beaconFrame->BSSID[0], beaconFrame->BSSID[1], beaconFrame->BSSID[2], beaconFrame->BSSID[3], beaconFrame->BSSID[4], beaconFrame->BSSID[5]);

                struct TaggedParameter* taggedParameter;
                taggedParameter = (struct TaggedParameter*)(packet + radiotap->len + 36);

                if (taggedParameter->tagNumber == 0x00) {
                    for (int i = 0; i < taggedParameter->len; i++) {
                        ESSID[i] = taggedParameter->data[i];
                    }
                    ESSID[taggedParameter->len] = '\0';
                }

                stringBSSID = BSSID;
                stringESSID = ESSID;
                auto it = Beacons.find(stringBSSID);

                PWRs[stringBSSID] = radiotap->anteSig;

                if ((radiotap->channelFlag & 0x0080) == 0x0080) {
                    CHs[stringBSSID] = ((radiotap->channelFreq - 2412) / 5) + 1;
                }
                else if ((radiotap->channelFlag & 0x0100) == 0x0100) {
                    CHs[stringBSSID] = ((radiotap->channelFreq - 5160) / 5) + 32;
                }

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
            case 0x88: {
                // printf("QoS Data\n");
                struct QoSData* qoSData = (struct QoSData*)(packet + radiotap->len);
                sprintf((char*)BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", qoSData->BSSID[0], qoSData->BSSID[1], qoSData->BSSID[2], qoSData->BSSID[3], qoSData->BSSID[4], qoSData->BSSID[5]);
                stringBSSID = BSSID;
                sprintf((char*)STATION, "%02x:%02x:%02x:%02x:%02x:%02x", qoSData->sourAddr[0], qoSData->sourAddr[1], qoSData->sourAddr[2], qoSData->sourAddr[3], qoSData->sourAddr[4], qoSData->sourAddr[5]);
                stringSTATION = STATION;

                STATIONs[stringSTATION] = stringBSSID;

                break;
            }
            case 0x94:
                // printf("Block Ack\n");
                break;
            case 0xb4:
                // printf("Request to send\n");
                break;
            case 0xc4:
                // printf("Clear to send\n");
                break;
            case 0xc8: {
                // printf("QoS Null function\n");
                struct QoSNullFunction* qoSNullFunction = (struct QoSNullFunction*)(packet + radiotap->len);
                sprintf((char*)BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", qoSNullFunction->BSSID[0], qoSNullFunction->BSSID[1], qoSNullFunction->BSSID[2], qoSNullFunction->BSSID[3], qoSNullFunction->BSSID[4], qoSNullFunction->BSSID[5]);
                stringBSSID = BSSID;
                sprintf((char*)STATION, "%02x:%02x:%02x:%02x:%02x:%02x", qoSNullFunction->sourAddr[0], qoSNullFunction->sourAddr[1], qoSNullFunction->sourAddr[2], qoSNullFunction->sourAddr[3], qoSNullFunction->sourAddr[4], qoSNullFunction->sourAddr[5]);
                stringSTATION = STATION;

                STATIONs[stringSTATION] = stringBSSID;

                break;
            }
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
            printf("%s%20d%12d%12d\t%-32s\n", pair.first.c_str(), PWRs[pair.first], pair.second, CHs[pair.first], ESSIDs[pair.first].c_str());
        }

        printf("\n%s%32s\n", "BSSID", "STATION");

        for (const auto& pair : STATIONs) {
            printf("%s%20s\n", STATIONs[pair.first].c_str(), pair.first.c_str());
        }
        // sleep(0.1);
	}

    // printf("Beacons\n");
    for (const auto& pair : Beacons) {
        printf("%s%20d%12d%12d\t%-32s\n", pair.first.c_str(), PWRs[pair.first], pair.second, CHs[pair.first], ESSIDs[pair.first].c_str());
    }

    printf("\n%s%32s\n", "BSSID", "STATION");

    for (const auto& pair : STATIONs) {
        printf("%s%20s\n", STATIONs[pair.first].c_str(), pair.first.c_str());
    }

	pcap_close(pcap);
}