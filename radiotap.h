#pragma once
#pragma pack(1)

#include <cstdint>
#include <list>
#include <stdio.h>

struct Radiotap {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    // std::list<uint32_t> present;
    // std::list<uint32_t>::iterator iter = present.begin();
    uint32_t present;
};

struct AfterPresent {
    uint8_t flag;
    uint8_t dataRate;
    uint16_t chanFreq;
    uint16_t chanFlag;
    uint8_t anteSig;
};

struct Dot11Frame {
    uint8_t type;
    uint8_t flag;
};

struct FixedParameters {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capacityInfo;
};

struct SSIDParameter {
    uint8_t elementID;
    uint8_t len;
    uint8_t SSID[32];
};

struct BeaconFrame : Dot11Frame {
    uint16_t duration;
    uint8_t destAddr[6];
    uint8_t sourAddr[6];
    uint8_t BSSID[6];
    uint16_t seqControl;
    struct FixedParameters fixedParameters;
    // uint64_t timestamp;
    // uint16_t beaconInterval;
    // uint16_t capacityInfo;
    struct SSIDParameter ssidParameter;
};

struct NullFunction : Dot11Frame {

};

struct Acknowledgement : Dot11Frame {

};

struct PackerInfo {
    uint8_t BSSID[12];
    // int8_t PWR;
    int Beacons;
    // int Data;
    // int CH;
    // int MB;
    // char* ENC;
    // char* CIPHER;
    // char* AUTH;
    char ESSID[32];
};

void printBSSID(uint8_t* BSSID);