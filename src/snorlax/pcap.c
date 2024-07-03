/**
 * @file        snorlax/pcap.c
 * @brief       packet capture lib source file
 * @details     패킷 캡쳐와 관련한 구현 파일
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 3, 2024
 */

 #include "pcap.h"

 #include "pcap/packet.h"

extern snorlax_pcap_packet_t * snorlax_pcap_packet_gen(const char * dev, snorlax_pcap_packet_handler_t handler) {
#ifndef   RELEASE
    snorlaxdbg(dev == nil, false, "critical", "");
    snorlaxdbg(handler == nil, false, "critical", "");
#endif // RELEASE

    return pcap_packet_gen(dev, (pcap_packet_handler_t) handler);
}

extern int32_t snorlax_pcap_packet_run(snorlax_pcap_packet_t * packet) {
#ifndef   RELEASE
    snorlaxdbg(packet == nil, false, "critical", "");
#endif // RELEASE

    pcap_packet_on(packet);

    int32_t ret = pcap_packet_loop(packet);

    packet = pcap_packet_rem(packet);

    return ret;
}

extern int64_t snorlax_pcap_packet_header_second_get(snorlax_pcap_packet_header_t * header) {
    return ((pcap_packet_header_t *) header)->ts.tv_sec;
}

extern int64_t snorlax_pcap_packet_header_unisecond_get(snorlax_pcap_packet_header_t * header) {
    return ((pcap_packet_header_t *) header)->ts.tv_usec;
}

extern int32_t snorlax_pcap_packet_header_capturelen_get(snorlax_pcap_packet_header_t * header) {
    return ((pcap_packet_header_t *) header)->caplen;
}

extern int32_t snorlax_pcap_packet_header_len_get(snorlax_pcap_packet_header_t * header) {
    return ((pcap_packet_header_t *) header)->len;
}
