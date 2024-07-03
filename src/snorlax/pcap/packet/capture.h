/**
 * @file        snorlax/pcap/packet/capture.h
 * @brief
 * @details
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 4, 2024
 */

#ifndef   __SNORLAX__PCAP_PACKET_CAPTURE__H__
#define   __SNORLAX__PCAP_PACKET_CAPTURE__H__

#include <snorlax/pcap/packet.h>

___expose struct pcap_packet_capture;
struct pcap_packet_capture_func;

___expose typedef struct pcap_packet_capture      pcap_packet_capture_t;
typedef struct pcap_packet_capture_func pcap_packet_capture_func_t;

typedef int32_t (*pcap_packet_capture_execute_t)(___notnull pcap_packet_capture_t *);

struct pcap_packet_capture {
    pcap_packet_capture_func_t * func;
    sync_t * sync;

    pcap_packet_capture_execute_t execute;

    pcap_packet_t * packet;
};

struct pcap_packet_capture_func {
    pcap_packet_capture_t * (*rem)(___notnull pcap_packet_capture_t *);
};

extern pcap_packet_capture_t * pcap_packet_capture_gen(const char * dev, pcap_packet_handler_t handler);

#endif // __SNORLAX__PCAP_PACKET_CAPTURE__H__