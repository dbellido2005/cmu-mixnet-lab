/**
 * Copyright (C) 2023 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#ifndef MIXNET_NODE_H_
#define MIXNET_NODE_H_

#include "address.h"
#include "config.h"
#include "packet.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    void run_node(void *const handle,
                  volatile bool *const keep_running,
                  const struct mixnet_node_config c);

    // STP configuration
    typedef struct spanning_tree
    {
        mixnet_address root_addr;    // Mixnet address of the root
        uint8_t next_hop_port;       // Port of next hop to root
        mixnet_address next_hop_adr; // Mixnet address of next hop to root
        uint16_t path_len;           // Path length to root

        uint8_t *open_ports;          // Mixnet address of next hop to root
        mixnet_address *port_to_addr; // Mixnet address at node connected at each port
    } spanning_tree;

    typedef struct mixing_buffer
    {
        mixnet_packet **packet_pointers; // List of packet pointers
        uint16_t count;                  // Packets currently stored
        uint16_t capacity;               // capacity = mixing_factor
    } mixing_buffer;

#ifdef __cplusplus
}
#endif

#endif // MIXNET_NODE_H_
