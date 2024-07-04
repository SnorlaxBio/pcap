/**
 * @file        snorlax/pcap/main.c
 * @brief
 * @details
 * 
 * @author      snorlax <ceo@snorlax.bio>
 * @since       July 4, 2024
 */

#include <stdio.h>

#include <snorlax/pcap.h>
#include <snorlax/protocol/ethernet.h>

static void snorlax_pcap_packet_handler(uint8_t * user, snorlax_pcap_packet_header_t * header, const uint8_t * packet);
static void snorlax_pcap_packet_debug(FILE * fp, uint8_t * user, snorlax_pcap_packet_header_t * header, const uint8_t * packet);

static void print(uint8_t * user, snorlax_pcap_packet_header_t * header, const uint8_t * packet);

int main(int argc, char ** argv) {
    snorlax_pcap_packet_t * packet = snorlax_pcap_packet_gen("eth0", snorlax_pcap_packet_handler);

    return snorlax_pcap_packet_run(packet);
}

static void snorlax_pcap_packet_handler(uint8_t * user, snorlax_pcap_packet_header_t * header, const uint8_t * packet) {
    snorlax_pcap_packet_debug(stdout, user, header, packet);
}

static void snorlax_pcap_packet_debug(FILE * stream, uint8_t * user, snorlax_pcap_packet_header_t * header, const uint8_t * packet) {
    fprintf(stream, "%ld.%06ld\n", snorlax_pcap_packet_header_second_get(header), snorlax_pcap_packet_header_unisecond_get(header));

    ethernet_protocol_debug(stream, packet);

    fprintf(stream, "\n");
}
