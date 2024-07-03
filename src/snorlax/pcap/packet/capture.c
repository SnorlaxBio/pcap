/**
 * @file        snorlax/pcap/packet/capture.c
 * @brief
 * @details
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 4, 2024
 */

#include <stdlib.h>

#include "capture.h"

static int32_t pcap_packet_capture_execute_func(___notnull pcap_packet_capture_t * command);

static pcap_packet_capture_t * pcap_packet_capture_func_rem(___notnull pcap_packet_capture_t * command);

static pcap_packet_capture_func_t func = {
    pcap_packet_capture_func_rem
};

extern pcap_packet_capture_t * pcap_packet_capture_gen(const char * dev, pcap_packet_handler_t handler) {
#ifndef   RELEASE
    snorlaxdbg(dev == nil, false, "critical", "");
#endif // RELEASE

    pcap_packet_capture_t * command = (pcap_packet_capture_t *) calloc(1, sizeof(pcap_packet_capture_t));

    command->func = address_of(func);
    command->packet = pcap_packet_gen(dev, handler);
    command->execute = pcap_packet_capture_execute_func;

    if(pcap_packet_on(command->packet) == fail) {
#ifndef   RELEASE
        snorlaxdbg(false, true, "warning", "");
#endif // RELEASE
    }

    return command;
}

static int32_t pcap_packet_capture_execute_func(___notnull pcap_packet_capture_t * command) {
#ifndef   RELEASE
    snorlaxdbg(command == nil, false, "critical", "");
    snorlaxdbg(command->packet->handle == nil, false, "critical", "");
#endif // RELEASE

    pcap_packet_pop(command->packet, nil);

    return success;
}

static pcap_packet_capture_t * pcap_packet_capture_func_rem(___notnull pcap_packet_capture_t * command) {
#ifndef   RELEASE
    snorlaxdbg(command == nil, false, "critical", "");
#endif // RELEASE

    pcap_packet_off(command->packet, nil);
    command->packet = pcap_packet_rem(command->packet);

    return nil;
}
