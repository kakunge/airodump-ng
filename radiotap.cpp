#include "radiotap.h"

void printBSSID(uint8_t* BSSID) {
    printf("BSSID : %02x:%02x:%02x:%02x:%02x:%02x\n", BSSID[0], BSSID[1], BSSID[2], BSSID[3], BSSID[4], BSSID[5]);
}