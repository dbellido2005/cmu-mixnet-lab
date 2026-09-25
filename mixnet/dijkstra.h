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
#ifndef MIXNET_DIJKSTRA_H_
#define MIXNET_DIJKSTRA_H_

#include "address.h"
#include "config.h"
#include "graph.h"
#include "packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Per-node Dijkstra bookkeeping: best cost found so far to reach this
     * node, the predecessor address on that best path (for route
     * reconstruction), and whether this node's shortest path is finalized.
     */
    typedef struct dijkstra_node
    {
        mixnet_address address;
        uint32_t cost;
        mixnet_address predecessor;
        bool visited;
    } dijkstra_node;

    /**
     * Dynamically-growing array of dijkstra_node, indexed 0..count-1.
     */
    typedef struct dijkstra_table
    {
        struct dijkstra_node *entries;
        size_t count;
        size_t capacity;
    } dijkstra_table;

    /**
     * Builds a dijkstra_node value for addr with the given cost,
     * predecessor, and visited state.
     */
    struct dijkstra_node create_dijkstra_node(mixnet_address addr, uint32_t cost,
                                               mixnet_address pred, bool is_visited);

    /**
     * Allocates a dijkstra_table seeded from graph's current entries:
     * self_addr gets cost 0 / INVALID_MIXADDR / visited, every other
     * node in graph gets cost UINT32_MAX / INVALID_MIXADDR / unvisited.
     */
    struct dijkstra_table *init_dijkstra_table(struct topology_graph *graph, mixnet_address self_addr);

    /**
     * Linear scan for the dijkstra_node with the given address.
     * Returns NULL if not present in the table yet.
     */
    struct dijkstra_node *find_dijkstra_node(struct dijkstra_table *table, mixnet_address target);

    /**
     * Builds a dijkstra_node for addr (via create_dijkstra_node) and
     * appends it to table, growing table->entries if needed. Does not
     * check for an existing entry with the same address first -- that's
     * the caller's responsibility.
     * Returns a pointer to the newly-appended entry.
     */
    struct dijkstra_node *add_dijkstra_entry(struct dijkstra_table *table, mixnet_address addr,
                                              uint32_t cost, mixnet_address pred, bool is_visited);

    /**
     * Rebuilds a dijkstra_table from scratch for graph/self_addr (via
     * init_dijkstra_table).
     */
    struct dijkstra_table *compute_dijkstra(struct topology_graph *graph, mixnet_address self_addr,
                                             const struct mixnet_node_config c);

    /**
     * Computes the route from routing_header->src_address to
     * routing_header->dst_address (via d_table) and writes it into
     * routing_header: sets route_length and fills route[] with the
     * intermediate hops. For a DATA packet, first memmoves the existing
     * data payload further into the buffer to make room for route[].
     * If is_random is set (the caller rolls this per do_random_routing
     * and its own probability), attempts a randomized detour route (see
     * compute_random_route in dijkstra.c) before falling back to the
     * plain dijkstra route -- graph is needed for that search.
     */
    void add_routing_header(struct dijkstra_table *d_table, mixnet_packet *packet, bool is_data_packet,
                             struct topology_graph *graph, const struct mixnet_node_config c, bool is_random);

    /**
     * Reverses routing_header in place for a reply travelling back along
     * the same path: swaps src_address/dst_address, reverses route[], and
     * resets hop_index to 0.
     */
    void reverse_route(mixnet_packet_routing_header *routing_header);

    /**
     * Frees a dijkstra_table: the entries array, then the table struct.
     * dijkstra_node has no nested allocations of its own.
     */
    void free_dijkstra_table(struct dijkstra_table *table);

#ifdef __cplusplus
}
#endif

#endif // MIXNET_DIJKSTRA_H_
