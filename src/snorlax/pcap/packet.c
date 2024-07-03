/**
 * @file        snorlax/packet.c
 * @brief
 * @details
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 7, 2024
 */

#include <string.h>
#include <stdlib.h>

#include "packet.h"

static void pcap_packet_cancel_func_default(pcap_packet_t * packet);

static pcap_packet_t * pcap_packet_func_rem(pcap_packet_t * packet);
static int32_t pcap_packet_func_on(pcap_packet_t * packet);
static int32_t pcap_packet_func_off(pcap_packet_t * packet, pcap_packet_cancel_t cancel);
static int32_t pcap_packet_func_loop(pcap_packet_t * packet);
static int32_t pcap_packet_func_pop(pcap_packet_t * packet, pcap_packet_handler_t handler);

static pcap_packet_func_t func = {
    pcap_packet_func_rem,
    pcap_packet_func_on,
    pcap_packet_func_off,
    pcap_packet_func_loop,
    pcap_packet_func_pop
};

extern pcap_packet_t * pcap_packet_gen(const char * dev, pcap_packet_handler_t handler) {
#ifndef   RELEASE
    snorlaxdbg(dev == nil, false, "critical", "");
#endif // RELEASE

    pcap_packet_t * packet = (pcap_packet_t *) calloc(1, sizeof(pcap_packet_t));

    packet->func = address_of(func);
    packet->dev = strdup(dev);
    packet->handler = handler;

    return packet;
}

static pcap_packet_t * pcap_packet_func_rem(pcap_packet_t * packet) {
#ifndef   RELEASE
    snorlaxdbg(packet == nil, false, "critical", "");
    snorlaxdbg(packet->handle, false, "critical", "");
#endif // RELEASE

    packet->dev = memory_rem(packet->dev);

    free(packet);

    return nil;
}

static int32_t pcap_packet_func_on(pcap_packet_t * packet) {
#ifndef   RELEASE
    snorlaxdbg(packet == nil, false, "critical", "");
    snorlaxdbg(packet->handle, false, "critical", "");
#endif // RELEASE

    char errbuf[PCAP_BUF_SIZE];
    errbuf[0] = 0;

    packet->cancel = nil;
    packet->handle = pcap_open_live(packet->dev, BUFSIZ, 1, 1000, errbuf);

    if(packet->handle == nil) {
#ifndef   RELEASE
        snorlaxdbg(false, true, "warning", "%s", errbuf);
#endif // RELEASE

        return fail;
    }

    return success;
}

static int32_t pcap_packet_func_off(pcap_packet_t * packet, pcap_packet_cancel_t cancel) {
#ifndef   RELEASE
    snorlaxdbg(packet == nil, false, "critical", "");
    snorlaxdbg(packet->handle, false, "critical", "");
#endif // RELEASE

    if(packet->handle) {
        packet->cancel = cancel ? cancel : pcap_packet_cancel_func_default;
        if((packet->status & pcap_packet_state_on) == 0) {
            pcap_close(packet->handle);
            packet->handle = nil;
            packet->cancel(packet);
            packet->cancel = nil;
        } else {
            pcap_breakloop(packet->handle);
        }
    }
    
    return success;
}

static int32_t pcap_packet_func_loop(pcap_packet_t * packet) {
#ifndef   RELEASE
    snorlaxdbg(packet == nil, false, "critical", "");
    snorlaxdbg(packet->handle == nil, false, "critical", "");
#endif // RELEASE

    packet->status = packet->status | pcap_packet_state_on;

    pcap_loop(packet->handle, 0, packet->handler, nil);

    packet->status = packet->status & (~pcap_packet_state_on);
    
    pcap_close(packet->handle);
    packet->handle = nil;

    if(packet->cancel) {
        packet->cancel(packet);
        packet->cancel = nil;
    }

    return success;
}

static int32_t pcap_packet_func_pop(pcap_packet_t * packet, pcap_packet_handler_t handler) {
#ifndef   RELEASE
    snorlaxdbg(packet == nil, false, "critical", "");
    snorlaxdbg(packet->handle == nil, false, "critical", "");
    snorlaxdbg(packet->handler == nil, false, "critical", "");
#endif // RELEASE

    char errbuf[PCAP_BUF_SIZE];

    pcap_setnonblock(packet->handle, 1, errbuf);
    int32_t n = pcap_dispatch(packet->handle, 1024, handler ? handler : packet->handler, nil);
    pcap_setnonblock(packet->handle, 0, errbuf);
}

static void pcap_packet_cancel_func_default(pcap_packet_t * packet) {

}
