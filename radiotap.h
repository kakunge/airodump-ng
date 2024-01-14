#pragma once

#include <cstdint>
#include <list>

struct Radiotap {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    // std::list<uint32_t> present;
    // std::list<uint32_t>::iterator iter = present.begin();
    uint32_t present;
} __attribute__((packed));

struct AfterPresent {
    uint8_t flag;
    uint8_t dataRate;
    uint16_t chanFreq;
    uint16_t chanFlag;
    uint8_t anteSig;
} __attribute__((packed));

struct Dot11Frame {
    uint8_t type;
    uint8_t flag;
} __attribute__((packed));

struct FixedParameters {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capacityInfo;
} __attribute__((packed));

struct SSIDParameter {
    uint8_t elementID;
    uint8_t len;
    uint8_t SSID[32];
} __attribute__((packed));

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
} __attribute__((packed));

struct NullFunction : Dot11Frame {

} __attribute__((packed));

struct Acknowledgement : Dot11Frame {

} __attribute__((packed));