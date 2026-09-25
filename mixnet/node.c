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
#include "node.h"
#include <time.h>

#include "connection.h"
#include "packet.h"
#include "helpers.h"
#include "graph.h"
#include "dijkstra.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/time.h>
#include <string.h>

spanning_tree *init_stp(const struct mixnet_node_config c, spanning_tree *STP)
{
    bool make_new_STP = (STP == NULL);
    if (make_new_STP)
    {
        STP = xcalloc(1, sizeof(spanning_tree));
    }
    STP->root_addr = c.node_addr;
    STP->next_hop_adr = c.node_addr;
    STP->next_hop_port = c.num_neighbors + 1; // CAUTION: will be NULL dereference if accessed
    STP->path_len = 0;
    if (make_new_STP)
    {
        STP->open_ports = xcalloc(c.num_neighbors, sizeof(*STP->open_ports));
        STP->port_to_addr = xcalloc(c.num_neighbors, sizeof(*STP->port_to_addr));
    }
    for (int i = 0; i < c.num_neighbors; i++)
    {
        STP->open_ports[i] = 1; // start open;
    }
    return STP;
}

/* Terminology:     - stp_header -> just the header
                    - stp_payload -> just the payload
                    - stp_packet -> header + payload (adjacent in heap) */

mixnet_packet *init_stp_packet(mixnet_address root_address,
                               mixnet_address node_address,
                               uint16_t path_length)
{
    size_t total_size = sizeof(mixnet_packet_stp) + sizeof(mixnet_packet);
    mixnet_packet *header = xcalloc(1, total_size);
    header->type = PACKET_TYPE_STP;
    header->total_size = total_size; // 18 = 12 + 6
    mixnet_packet_stp *payload = (mixnet_packet_stp *)header->payload;
    payload->root_address = root_address;
    payload->path_length = path_length;
    payload->node_address = node_address;
    return header;
}

mixnet_packet *init_lsa_packet(const struct mixnet_node_config c, spanning_tree *STP)
{
    size_t total_size = sizeof(mixnet_packet) + sizeof(mixnet_packet_lsa) + c.num_neighbors * sizeof(mixnet_lsa_link_params);
    mixnet_packet *header = xcalloc(1, total_size);
    header->type = PACKET_TYPE_LSA;
    header->total_size = total_size; // 12 + (4 + (4n))
    mixnet_packet_lsa *payload = (mixnet_packet_lsa *)header->payload;
    payload->node_address = c.node_addr;
    payload->neighbor_count = c.num_neighbors;
    for (int i = 0; i < c.num_neighbors; i++)
    {
        payload->links[i].cost = c.link_costs[i];
        payload->links[i].neighbor_mixaddr = STP->port_to_addr[i];
    }
    return header;
}

mixnet_packet *init_flood_packet(void)
{
    mixnet_packet *flood_header = xcalloc(1, sizeof(mixnet_packet));
    flood_header->type = PACKET_TYPE_FLOOD;
    flood_header->total_size = 12;
    return flood_header;
}

mixnet_packet *make_packet(const struct mixnet_node_config c, spanning_tree *STP,
                           mixnet_packet_type_t packet_type)
{
    mixnet_packet *packet = NULL;
    if (packet_type == PACKET_TYPE_STP)
    {
        packet = init_stp_packet(STP->root_addr, c.node_addr, STP->path_len);
    }
    else if (packet_type == PACKET_TYPE_FLOOD)
    {
        packet = init_flood_packet();
    }
    else if (packet_type == PACKET_TYPE_LSA)
    {
        packet = init_lsa_packet(c, STP);
    }
    // data & ping ->use packet you get, do not remake
    return packet;
}

/* Specifications:
    only_open = true -> will only broadcast to open ports
    exclude_port = n -> will NOT broadcast to n'th port (example: input ports)
    snd_user = true -> will broadcast to user port (n+1)
    packet != NULL -> broadcast a copy of this packet
    packet = NULL -> broadcast an *updated* packet of type packet_type
    *updated* -> flood = default, stp = uses STP to fill out info
                 data = should never rcv this
*/
void broadcast(void *const handle, const struct mixnet_node_config c,
               spanning_tree *STP, bool only_open, int exclude_port,
               bool snd_user, mixnet_packet_type_t packet_type,
               mixnet_packet *packet)
{
    if (packet == NULL)
    {
        packet = make_packet(c, STP, packet_type);
    }

    int n = c.num_neighbors;
    for (int i = 0; i < n; i++)
    {
        bool is_excluded = (i == exclude_port);
        bool check_open = (only_open && (STP->open_ports[i] == 0));
        if (is_excluded || check_open)
        {
            continue;
        }

        mixnet_packet *packet_cpy = deep_copy_packet(packet);
        mixnet_send(handle, i, packet_cpy);
    }

    if (snd_user)
    {
        mixnet_packet *packet_cpy = deep_copy_packet(packet);
        mixnet_send(handle, n, packet_cpy);
    }
    free(packet);
}

// CAREFUL: make sure to call this before updating the next_hop_port
void update_open_ports(spanning_tree *STP, uint8_t input_port, const struct mixnet_node_config c)
{
    // avoids segfault when port = default
    if (STP->next_hop_port != c.num_neighbors + 1)
    {
        STP->open_ports[STP->next_hop_port] = 0; // close old port
    }
    STP->open_ports[input_port] = 1; // open new port
}

bool update_stp(spanning_tree *STP, mixnet_packet_stp *rcvd_stp_packet,
                uint8_t input_port, bool node_updated, const struct mixnet_node_config c,
                bool print_flag, struct timeval *last_heartbeat)
{
    if (rcvd_stp_packet->root_address < STP->root_addr)
    {
        // new root
        mixnet_address old_root = STP->root_addr;
        update_open_ports(STP, input_port, c);
        STP->root_addr = rcvd_stp_packet->root_address;
        STP->next_hop_port = input_port;
        STP->next_hop_adr = rcvd_stp_packet->node_address;
        STP->path_len = rcvd_stp_packet->path_length + 1;
        node_updated = true;
        assert(gettimeofday(last_heartbeat, NULL) == 0);

        if (print_flag)
        {
            dlog(c, "[DEBUG] New root found! %u -> %u (path: %u)",
                 old_root, rcvd_stp_packet->root_address, rcvd_stp_packet->path_length + 1);
        }
    }
    else if (rcvd_stp_packet->root_address == STP->root_addr &&
             rcvd_stp_packet->path_length + 1 < STP->path_len)
    {
        // shorter path
        update_open_ports(STP, input_port, c);
        STP->next_hop_port = input_port;
        STP->next_hop_adr = rcvd_stp_packet->node_address;
        STP->path_len = rcvd_stp_packet->path_length + 1;
        node_updated = true;
        assert(gettimeofday(last_heartbeat, NULL) == 0);

        if (print_flag)
        {
            dlog(c, "[DEBUG] Shorter path found! %u -> %u (path: %u)",
                 STP->path_len, rcvd_stp_packet->path_length + 1, input_port);
            print_stp("Shorter Path", STP, c.num_neighbors, c);
        }
    }
    else if (rcvd_stp_packet->root_address == STP->root_addr &&
             rcvd_stp_packet->path_length + 1 == STP->path_len &&
             rcvd_stp_packet->node_address < STP->next_hop_adr)
    {
        // break ties: same length path but smaller addr
        update_open_ports(STP, input_port, c);
        STP->next_hop_port = input_port;
        STP->next_hop_adr = rcvd_stp_packet->node_address;
        node_updated = true;

        if (print_flag)
        {
            dlog(c, "[DEBUG] same length path but smaller addr");
            print_stp("Tiebreak", STP, c.num_neighbors, c);
        }
    }
    else if (rcvd_stp_packet->root_address == STP->root_addr &&
             rcvd_stp_packet->path_length < STP->path_len + 1 &&
             STP->next_hop_adr != rcvd_stp_packet->node_address)
    {
        // block nodes with shorter paths (except parent)
        (STP->open_ports)[input_port] = 0;

        if (print_flag)
        {
            dlog(c, "[DEBUG] Blocking node %i (shorter path exists)", STP->port_to_addr[input_port]);
            print_stp("Block", STP, c.num_neighbors, c);
        }
    }
    else if (rcvd_stp_packet->root_address == STP->root_addr &&
             rcvd_stp_packet->path_length == STP->path_len + 1)
    {
        // open ports to potential children
        (STP->open_ports)[input_port] = 1;

        if (print_flag)
        {
            dlog(c, "[DEBUG] open port to potential child");
            print_stp("Open", STP, c.num_neighbors, c);
        }
    }
    return node_updated;
}

void heartbeat_logic(struct timeval *last_heartbeat, struct timeval *curr_time,
                     spanning_tree *STP, const struct mixnet_node_config c, void *const handle,
                     bool print_flag, uint16_t no_excluded_ports)
{
    // compute time difference
    assert(gettimeofday(curr_time, NULL) == 0);
    uint32_t heartbeat_diff = (curr_time->tv_sec - last_heartbeat->tv_sec) * 1000 +
                              (curr_time->tv_usec - last_heartbeat->tv_usec) / 1000;

    // send heartbeats
    bool is_root = (STP->root_addr == c.node_addr);
    if (is_root && (heartbeat_diff > c.root_hello_interval_ms))
    {
        broadcast(handle, c, STP, true, no_excluded_ports, false, PACKET_TYPE_STP, NULL);
        assert(gettimeofday(last_heartbeat, NULL) == 0);
    }
    // reelect root
    else if (!is_root && (heartbeat_diff > c.reelection_interval_ms))
    {
        init_stp(c, STP);
        broadcast(handle, c, STP, false, no_excluded_ports, false, PACKET_TYPE_STP, NULL);
        assert(gettimeofday(last_heartbeat, NULL) == 0);
        if (print_flag)
        {
            dlog(c, "[DEBUG] Root disconnected");
        }
    }
}

// Fails if addr not in neighbors
uint16_t addr_to_port(mixnet_address target_addr, spanning_tree *STP,
                      const struct mixnet_node_config c)
{
    for (int port = 0; port < c.num_neighbors; port++)
    {
        if (STP->port_to_addr[port] == target_addr)
        {
            return port;
        }
    }
    dlog(c, "[ERROR] addr_to_port: address %u not found among neighbors", target_addr);
    exit(EXIT_FAILURE);
}

void lsa_logic(struct timeval *curr_time, struct timeval *lsa_timer,
               bool *lsa_has_flooded, const struct mixnet_node_config c,
               void *const handle, spanning_tree *STP, bool print_flag)
{
    if (*lsa_has_flooded)
    {
        return; // already sent lsa message
    }

    // timer
    assert(gettimeofday(curr_time, NULL) == 0);
    uint32_t lsa_diff = (curr_time->tv_sec - lsa_timer->tv_sec) * 1000 +
                        (curr_time->tv_usec - lsa_timer->tv_usec) / 1000;

    if (lsa_diff > 3 * c.reelection_interval_ms)
    {
        if (print_flag)
        {
            dlog(c, "[LSA] flooding own link state (quiet for %u ms > threshold %u ms)",
                 lsa_diff, 3 * c.reelection_interval_ms);
        }
        uint16_t no_excluded_ports = c.num_neighbors + 1;
        broadcast(handle, c, STP, false, no_excluded_ports, false, PACKET_TYPE_LSA, NULL);
        *lsa_has_flooded = true;
    }
}

void send_to_nxt_hop(const struct mixnet_node_config c, void *const handle,
                     spanning_tree *STP,
                     mixnet_packet *packet, bool print_flag)
{
    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header *)&(packet->payload);
    bool is_data_packet = packet->type == PACKET_TYPE_DATA;
    mixnet_address nxt_addr;
    if (routing_header->route_length == routing_header->hop_index)
    {
        // destination is direct node
        nxt_addr = routing_header->dst_address;
    }
    else
    {
        nxt_addr = routing_header->route[routing_header->hop_index];
    }

    if (print_flag)
    {
        dlog(c, "[MIX] send_to_nxt_hop: src=%u dst=%u hop_index=%u route_length=%u -> nxt_addr=%u",
             routing_header->src_address, routing_header->dst_address,
             routing_header->hop_index, routing_header->route_length, nxt_addr);
    }

    uint16_t nxt_port = addr_to_port(nxt_addr, STP, c);

    if (print_flag)
    {
        dlog(c, "[%s] sending to next_hop=%u via port=%u",
             is_data_packet ? "DATA" : "PING", nxt_addr, nxt_port);
    }

    mixnet_send(handle, nxt_port, packet);
}

void reset_mixing_buffer(mixing_buffer *mixing_buffer, const struct mixnet_node_config c, bool print_flag)
{
    if (print_flag)
    {
        dlog(c, "[MIX] resetting buffer: had count=%u capacity=%u", mixing_buffer->count, mixing_buffer->capacity);
    }
    mixing_buffer->count = 0;
    for (int i = 0; i < mixing_buffer->capacity; i++)
    {
        mixing_buffer->packet_pointers[i] = NULL;
    }
}

void mix_and_send(const struct mixnet_node_config c, void *const handle,
                  spanning_tree *STP,
                  mixnet_packet *packet, bool print_flag, mixing_buffer *mixing_buffer)
{
    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header *)&(packet->payload);

    if (mixing_buffer->count < mixing_buffer->capacity - 1)
    {
        // store pointer
        if (print_flag)
        {
            dlog(c, "[MIX] buffering packet %u/%u: src=%u dst=%u hop_index=%u route_length=%u",
                 mixing_buffer->count + 1, mixing_buffer->capacity,
                 routing_header->src_address, routing_header->dst_address,
                 routing_header->hop_index, routing_header->route_length);
        }
        mixing_buffer->packet_pointers[mixing_buffer->count] = packet;
        mixing_buffer->count = mixing_buffer->count + 1;
    }
    else
    {
        // store last pointer
        if (print_flag)
        {
            dlog(c, "[MIX] buffering packet %u/%u (last slot, flushing): src=%u dst=%u hop_index=%u route_length=%u",
                 mixing_buffer->count + 1, mixing_buffer->capacity,
                 routing_header->src_address, routing_header->dst_address,
                 routing_header->hop_index, routing_header->route_length);
        }
        mixing_buffer->packet_pointers[mixing_buffer->count] = packet;

        // send all stored pointers
        for (int i = 0; i < mixing_buffer->capacity; i++)
        {
            if (print_flag)
            {
                dlog(c, "[MIX] flushing buffer slot %d/%u", i, mixing_buffer->capacity);
            }
            send_to_nxt_hop(c, handle, STP, mixing_buffer->packet_pointers[i], print_flag);
        }
        reset_mixing_buffer(mixing_buffer, c, print_flag);
    }
}

void send_buffer(const struct mixnet_node_config c, void *const handle,
                 spanning_tree *STP, bool print_flag, mixing_buffer *mixing_buffer)
{
    if (print_flag)
    {
        dlog(c, "[MIX] shutdown: flushing %u leftover buffered packet(s)", mixing_buffer->count);
    }

    // send all stored pointers
    for (int i = 0; i < mixing_buffer->count; i++)
    {
        if (print_flag)
        {
            dlog(c, "[MIX] shutdown flush slot %d/%u", i, mixing_buffer->count);
        }
        send_to_nxt_hop(c, handle, STP, mixing_buffer->packet_pointers[i], print_flag);
    }
}

mixing_buffer *init_mixing_buffer(const struct mixnet_node_config c)
{
    mixing_buffer *mixing_buffer = xcalloc(1, sizeof(struct mixing_buffer));
    mixing_buffer->packet_pointers = xcalloc(c.mixing_factor, sizeof(mixnet_packet *));
    mixing_buffer->count = 0;
    mixing_buffer->capacity = c.mixing_factor;
    return mixing_buffer;
}

void run_node(void *const handle,
              volatile bool *const keep_running,
              const struct mixnet_node_config c)
{
    srand(time(NULL)); // for randomness

    (void)c;
    (void)handle;
    bool print_flag = false;

    // Initialize STP & packets
    spanning_tree *STP = init_stp(c, NULL);

    uint16_t no_excluded_ports = c.num_neighbors + 1;
    broadcast(handle, c, STP, false, no_excluded_ports, false, PACKET_TYPE_STP, NULL);

    // Initialize Time
    struct timeval *last_heartbeat = xcalloc(1, sizeof(struct timeval)); // heartbeat
    assert(gettimeofday(last_heartbeat, NULL) == 0);
    struct timeval *curr_time = xcalloc(1, sizeof(struct timeval));
    struct timeval *ping_time = xcalloc(1, sizeof(struct timeval)); // ping
    struct timeval *lsa_timer = xcalloc(1, sizeof(struct timeval)); // lsa timer
    assert(gettimeofday(lsa_timer, NULL) == 0);
    bool lsa_has_flooded = false; // mark true when we have sent first flood package

    // Initialize receiving packet infrastructure
    uint8_t *port = xcalloc(1, sizeof(uint8_t));
    mixnet_packet **packet = xcalloc(1, sizeof(mixnet_packet *));

    // Initialize Graph
    topology_graph *graph = init_topology_graph(c.node_addr);
    dijkstra_table *d_table = init_dijkstra_table(graph, c.node_addr);

    // Initialize Mixing Buffer
    mixing_buffer *mixing_buffer = init_mixing_buffer(c);

    while (*keep_running)
    {

        // check TIMERS
        heartbeat_logic(last_heartbeat, curr_time, STP, c, handle, print_flag, no_excluded_ports);
        lsa_logic(curr_time, lsa_timer, &lsa_has_flooded, c, handle, STP, print_flag);

        // RECEIVE PACKETS
        int packets_rcv = mixnet_recv(handle, port, packet);

        if (packets_rcv > 0)
        {
            assert(packet != NULL);
            assert(*packet != NULL);

            bool is_user = (*port == c.num_neighbors);
            if (is_user)
            {
                if ((*packet)->type == PACKET_TYPE_FLOOD)
                {
                    // CH 1
                    if (print_flag)
                    {
                        dlog(c, "[FLOOD] originating from user, broadcasting to all open ports");
                    }
                    broadcast(handle, c, STP, true, no_excluded_ports, false, PACKET_TYPE_FLOOD, *packet);
                }
                else if (((*packet)->type == PACKET_TYPE_PING) ||
                         ((*packet)->type == PACKET_TYPE_DATA))
                {
                    // CH 2
                    // 1. compute route to dest
                    float p = 0;
                    bool is_random = false;
                    if (c.do_random_routing)
                    {
                        p = (float)rand() / (float)RAND_MAX;
                        is_random = (p >= 0.5); // pick random route 50% of times
                    }
                    bool is_data_packet = (*packet)->type == PACKET_TYPE_DATA;
                    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header *)&(*packet)->payload;
                    add_routing_header(d_table, *packet, is_data_packet, graph, c, is_random);

                    if (print_flag)
                    {
                        dlog(c, "[%s] originating from user: src=%u dst=%u route_len=%u",
                             is_data_packet ? "DATA" : "PING",
                             routing_header->src_address, routing_header->dst_address, routing_header->route_length);
                    }

                    // add ping information
                    if ((*packet)->type == PACKET_TYPE_PING)
                    {
                        (*packet)->total_size += sizeof(mixnet_packet_ping);
                        size_t route_bytes = routing_header->route_length * sizeof(mixnet_address);
                        mixnet_packet_ping *ping_payload = (mixnet_packet_ping *)((char *)routing_header + sizeof(mixnet_packet_routing_header) + route_bytes);
                        ping_payload->is_request = true;
                        assert(gettimeofday(ping_time, NULL) == 0);
                        ping_payload->send_time = (ping_time->tv_sec) * 1000 + (ping_time->tv_usec) / 1000; // in miliseconds

                        if (print_flag)
                        {
                            dlog(c, "[PING] sending request: dst=%u send_time=%llu ms",
                                 routing_header->dst_address, (unsigned long long)ping_payload->send_time);
                        }
                    }

                    // 2. mix, then pass to next hop
                    mix_and_send(c, handle, STP, *packet, print_flag, mixing_buffer);
                }
            }
            else
            {
                if ((*packet)->type == PACKET_TYPE_STP)
                { // CH 1
                    mixnet_packet_stp *rcvd_stp_packet = (mixnet_packet_stp *)((*packet)->payload);

                    if (print_flag)
                    {
                        dlog(c, "[DEBUG] rcvd STP on port=%u (root=%i, path_len=%i, node=%i)",
                             *port, rcvd_stp_packet->root_address, rcvd_stp_packet->path_length, rcvd_stp_packet->node_address);
                    }

                    // STP heartbeat detector
                    bool from_root = (rcvd_stp_packet->root_address == STP->root_addr);
                    bool parent_port = (*port == STP->next_hop_port);
                    bool is_heartbeat = from_root && parent_port;

                    if (is_heartbeat)
                    {
                        assert(gettimeofday(last_heartbeat, NULL) == 0);
                    }

                    if (print_flag)
                    {
                        dlog(c, "[DEBUG] rcvd STP on port=%u (root=%i, path_len=%i, node=%i)",
                             *port, rcvd_stp_packet->root_address, rcvd_stp_packet->path_length, rcvd_stp_packet->node_address);
                    }

                    // STP update
                    (STP->port_to_addr)[*port] = rcvd_stp_packet->node_address; // nei discovery
                    bool node_updated = update_stp(STP, rcvd_stp_packet, *port, false, c, print_flag, last_heartbeat);
                    if (node_updated)
                    {
                        // real STP state change (new root/shorter path/tie-break) --
                        // resets the "how long has STP been quiet" clock that
                        // lsa_logic uses to decide when to start LSA flooding.
                        assert(gettimeofday(lsa_timer, NULL) == 0);
                    }
                    if (node_updated || is_heartbeat)
                    {
                        // new better paths/roots will update heartbeat timer
                        broadcast(handle, c, STP, false, no_excluded_ports, false, PACKET_TYPE_STP, NULL);
                    }
                    free(*packet);
                }
                else if ((*packet)->type == PACKET_TYPE_LSA)
                {
                    // CH 2
                    if (print_flag)
                    {
                        mixnet_packet_lsa *lsa_payload = (mixnet_packet_lsa *)((*packet)->payload);
                        char links_buf[256] = {0};
                        size_t off = 0;
                        for (uint16_t i = 0; i < lsa_payload->neighbor_count && off < sizeof(links_buf); i++)
                        {
                            off += snprintf(links_buf + off, sizeof(links_buf) - off, "%u(cost=%u) ",
                                            lsa_payload->links[i].neighbor_mixaddr, lsa_payload->links[i].cost);
                        }
                        dlog(c, "[LSA] rcvd on port=%u from node=%u, neighbors: %s",
                             *port, lsa_payload->node_address, links_buf);
                    }

                    // 1. update local link state
                    bool graph_updated = update_graph(graph, *packet);

                    // 2. compute shortest paths
                    if (graph_updated)
                    {
                        if (print_flag)
                        {
                            dlog(c, "[LSA] graph changed, recomputing dijkstra table");
                        }
                        // fully recompute dijkstra table
                        free_dijkstra_table(d_table);
                        d_table = compute_dijkstra(graph, c.node_addr, c);

                        if (print_flag)
                        {
                            for (size_t i = 0; i < d_table->count; i++)
                            {
                                dijkstra_node entry = d_table->entries[i];
                                dlog(c, "[LSA]   d_table entry: addr=%u cost=%u pred=%u visited=%d",
                                     entry.address, entry.cost, entry.predecessor, entry.visited);
                            }
                        }
                    }

                    // 3. broadcast packet along STP
                    if (print_flag)
                    {
                        dlog(c, "[LSA] forwarding along STP, excluding port=%u", *port);
                    }
                    broadcast(handle, c, STP, true, *port, false, PACKET_TYPE_LSA, *packet);
                }
                else if ((*packet)->type == PACKET_TYPE_FLOOD && STP->open_ports[*port])
                {
                    // CH 1
                    if (print_flag)
                    {
                        dlog(c, "[FLOOD] rcvd on open port=%u, forwarding to other open ports + delivering to user", *port);
                    }
                    broadcast(handle, c, STP, true, *port, true, PACKET_TYPE_FLOOD, NULL);
                    free(*packet);
                }
                else if ((*packet)->type == PACKET_TYPE_FLOOD)
                {
                    // debug statement: rcvd on a BLOCKED port & dropped
                    if (print_flag)
                    {
                        dlog(c, "[FLOOD] rcvd on BLOCKED port=%u, dropping", *port);
                    }
                    free(*packet);
                }
                else
                { // ping or data
                    // CH 2
                    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header *)&((*packet)->payload);
                    bool is_dst = (c.node_addr == routing_header->dst_address);
                    if (is_dst)
                    {
                        if ((*packet)->type == PACKET_TYPE_DATA)
                        {
                            if (print_flag)
                            {
                                dlog(c, "[DATA] reached destination, delivering to user: src=%u", routing_header->src_address);
                            }
                            mixnet_send(handle, c.num_neighbors, *packet);
                        }
                        else if ((*packet)->type == PACKET_TYPE_PING)
                        {
                            // ping logic
                            size_t route_bytes = routing_header->route_length * sizeof(mixnet_address);
                            mixnet_packet_ping *ping_payload = (mixnet_packet_ping *)((char *)routing_header + sizeof(mixnet_packet_routing_header) + route_bytes);
                            if (ping_payload->is_request)
                            {
                                if (print_flag)
                                {
                                    dlog(c, "[PING] received request from src=%u, replying", routing_header->src_address);
                                }

                                // send received ping packet to user
                                mixnet_packet *packet_cpy = deep_copy_packet(*packet);
                                mixnet_send(handle, c.num_neighbors, packet_cpy);

                                // reverse path
                                reverse_route(routing_header);
                                ping_payload->is_request = false;
                                mixnet_send(handle, *port, *packet);
                            }
                            else
                            {
                                assert(gettimeofday(ping_time, NULL) == 0);
                                time_t curr_time = (ping_time->tv_sec * 1000) + (ping_time->tv_usec / 1000);
                                time_t RTT = curr_time - ping_payload->send_time;
                                printf("RTT to %u: %lld ms\n", routing_header->src_address, (long long)RTT);
                                fflush(stdout);
                                if (print_flag)
                                {
                                    dlog(c, "[PING] received reply from src=%u, RTT: %lld ms", routing_header->src_address, (long long)RTT);
                                }
                                mixnet_send(handle, c.num_neighbors, *packet);
                            }
                        }
                    }
                    else
                    {
                        // add mixing
                        routing_header->hop_index++; // pointing at adr of next node
                        mix_and_send(c, handle, STP, *packet, print_flag, mixing_buffer);
                    }
                }
            }
        }
    }
    // Send any packets left in buffer
    send_buffer(c, handle, STP, print_flag, mixing_buffer);

    //  Free memory
    free(STP->open_ports);
    free(STP->port_to_addr);
    free(STP);
    free(last_heartbeat);
    free(curr_time);
    free(port);
    free(packet);
    free(ping_time);
    free(lsa_timer);
    free_topology_graph(graph);
    free_dijkstra_table(d_table);
    free(mixing_buffer->packet_pointers);
    free(mixing_buffer);
}
