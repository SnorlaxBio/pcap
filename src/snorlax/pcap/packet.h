/**
 * @file        snorlax/pcap/packet.h
 * @brief
 * @details
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 7, 2024
 */

#ifndef   __SNORLAX__PCAP_PACKET__H__
#define   __SNORLAX__PCAP_PACKET__H__

#include <pcap/pcap.h>

#include <snorlax.h>

#define pcap_packet_state_on            (0x00000001U <<  0U)

___expose struct pcap_packet;
struct pcap_packet_func;

___expose typedef struct pcap_pkthdr    pcap_packet_header_t;
___expose typedef pcap_handler          pcap_packet_handler_t;
___expose typedef struct pcap_packet    pcap_packet_t;
typedef struct pcap_packet_func         pcap_packet_func_t;

typedef void (*pcap_packet_cancel_t)(pcap_packet_t *);

struct pcap_packet {
    pcap_packet_func_t * func;
    sync_t * sync;
    uint32_t status;
    char * dev;
    pcap_t * handle;
    pcap_packet_cancel_t cancel;
    pcap_packet_handler_t handler;
};

struct pcap_packet_func {
    pcap_packet_t * (*rem)(pcap_packet_t *);
    int32_t (*on)(pcap_packet_t *);
    int32_t (*off)(pcap_packet_t *, pcap_packet_cancel_t);
    int32_t (*loop)(pcap_packet_t *);
    int32_t (*pop)(pcap_packet_t *, pcap_packet_handler_t);
};

#define pcap_packet_rem(packet)             ((packet)->func->rem(packet))
#define pcap_packet_on(packet)              ((packet)->func->on(packet))
#define pcap_packet_off(packet, cancel)     ((packet)->func->off(packet, cancel))
#define pcap_packet_loop(packet)            ((packet)->func->loop(packet))
#define pcap_packet_pop(packet, callback)   ((packet)->func->pop(packet, callback))

extern pcap_packet_t * pcap_packet_gen(const char * dev, pcap_packet_handler_t handler);

#ifndef   RELEASE
extern void pcap_packet_handler_print(uint8_t * user, pcap_packet_header_t * header, const uint8_t * packet);
#endif // RELEASE

#endif // __SNORLAX__PCAP_PACKET__H__
