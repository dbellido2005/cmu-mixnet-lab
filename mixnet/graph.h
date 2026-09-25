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
#ifndef MIXNET_GRAPH_H_
#define MIXNET_GRAPH_H_

#include "address.h"
#include "packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * One neighbor entry in a topology node's adjacency list (built from LSAs).
     */
    typedef struct neighbor_list_node
    {
        mixnet_address neighbor_addr;
        uint16_t edge_cost;
        struct neighbor_list_node *nxt;
    } neighbor_list_node;

    /**
     * One node in the topology graph: its address plus the head of its
     * adjacency list.
     */
    typedef struct topology_node
    {
        mixnet_address address;
        struct neighbor_list_node *neighbors;
    } topology_node;

    /**
     * Dynamically-growing array of topology_node, indexed 0..count-1.
     * Grows via realloc as new node addresses are learned from LSAs.
     */
    typedef struct topology_graph
    {
        struct topology_node *nodes;
        size_t count;
        size_t capacity;
    } topology_graph;

    /**
     * Builds a topology_node value for addr with an empty adjacency list.
     */
    struct topology_node create_topology_node(mixnet_address addr);

    /**
     * Allocates a topology_graph containing a single default node for
     * self_addr (via create_topology_node).
     */
    struct topology_graph *init_topology_graph(mixnet_address self_addr);

    /**
     * Linear scan for the topology_node with the given address.
     * Returns NULL if not present in the graph yet.
     */
    struct topology_node *find_topology_node(struct topology_graph *graph, mixnet_address target);

    /**
     * Returns the topology_node for addr, creating (and appending) it first
     * if it isn't already in the graph. If out_created is non-NULL, it's
     * set to true when a new node was created, false when addr already
     * existed.
     */
    struct topology_node *get_or_create_topology_node(struct topology_graph *graph, mixnet_address addr, bool *out_created);

    /**
     * Adds a bidirectional edge (a <-> b, given cost) to the topology graph,
     * creating either endpoint's topology_node if it doesn't exist yet.
     * Skips an endpoint's insertion if that edge is already recorded there.
     * Returns true if this call created a new node and/or added a new
     * adjacency-list entry, false if the graph was already fully up to date.
     */
    bool add_topology_edge(struct topology_graph *graph, mixnet_address a, mixnet_address b, uint16_t cost);

    /**
     * Updates the topology graph from a received LSA packet: adds a
     * bidirectional edge for each of the advertising node's neighbors.
     * Returns true if this call changed the graph, false otherwise.
     */
    bool update_graph(struct topology_graph *graph, mixnet_packet *packet);

    /**
     * Frees a topology_graph: every neighbor_list_node in every node's
     * adjacency list, the nodes array itself, then the graph struct.
     */
    void free_topology_graph(struct topology_graph *graph);

#ifdef __cplusplus
}
#endif

#endif // MIXNET_GRAPH_H_
