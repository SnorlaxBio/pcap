/**
 * @file        snorlax/pcap.h
 * @brief
 * @details
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 3, 2024
 */

#ifndef   __SNORLAX__PCAP__H__
#define   __SNORLAX__PCAP__H__

#include <snorlax.h>

struct pcap_packet;

typedef struct pcap_packet snorlax_pcap_packet_t;
typedef void               snorlax_pcap_packet_header_t;

typedef void (*snorlax_pcap_packet_cancel_t)(snorlax_pcap_packet_t *);

typedef void (*snorlax_pcap_packet_handler_t)(uint8_t *, snorlax_pcap_packet_header_t *, const uint8_t *);

extern snorlax_pcap_packet_t * snorlax_pcap_packet_gen(const char * dev, snorlax_pcap_packet_handler_t handler);
extern int32_t snorlax_pcap_packet_run(snorlax_pcap_packet_t * packet);

extern int64_t snorlax_pcap_packet_header_second_get(snorlax_pcap_packet_header_t * header);
extern int64_t snorlax_pcap_packet_header_unisecond_get(snorlax_pcap_packet_header_t * header);
extern int32_t snorlax_pcap_packet_header_capturelen_get(snorlax_pcap_packet_header_t * header);
extern int32_t snorlax_pcap_packet_header_len_get(snorlax_pcap_packet_header_t * header);

// extern void pcap_packet_handler_print(uint8_t * user, pcap_packet_header_t * header, const uint8_t * packet);

#endif // __SNORLAX__PCAP__H__
