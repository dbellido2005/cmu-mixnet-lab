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
#include "graph.h"

#include "helpers.h"
#include "packet.h"
#include "config.h"

struct topology_node create_topology_node(mixnet_address addr)
{
    topology_node node;
    node.address = addr;
    node.neighbors = NULL;
    return node;
}

struct topology_graph *init_topology_graph(mixnet_address self_addr)
{
    topology_graph *graph = xcalloc(1, sizeof(struct topology_graph));
    graph->capacity = 1;
    graph->nodes = xcalloc(graph->capacity, sizeof(struct topology_node));
    graph->nodes[0] = create_topology_node(self_addr);
    graph->count = 1;
    return graph;
}

struct topology_node *find_topology_node(struct topology_graph *graph, mixnet_address target)
{
    for (size_t i = 0; i < graph->count; i++)
    {
        if (graph->nodes[i].address == target)
        {
            return &graph->nodes[i];
        }
    }
    return NULL;
}

/**
 * Grows graph->nodes if it's full. realloc() either extends the block
 * in place or allocates a new block, copies the old contents, and frees
 * the old block itself -- no separate free() needed.
 */
static void ensure_topology_capacity(struct topology_graph *graph)
{
    if (graph->count < graph->capacity)
    {
        return;
    }
    size_t new_capacity = (graph->capacity == 0) ? 4 : graph->capacity * 2;
    graph->nodes = xrealloc(graph->nodes, new_capacity * sizeof(struct topology_node));
    graph->capacity = new_capacity;
}

struct topology_node *get_or_create_topology_node(struct topology_graph *graph, 
                                                  mixnet_address addr, 
                                                  bool *out_created)
{
    struct topology_node *existing = find_topology_node(graph, addr);
    if (existing != NULL)
    {
        if (out_created != NULL)
        {
            *out_created = false;
        }
        return existing;
    }

    // node not in graph
    ensure_topology_capacity(graph);
    struct topology_node *node = &graph->nodes[graph->count];
    node->address = addr;
    node->neighbors = NULL;
    graph->count++;
    if (out_created != NULL)
    {
        *out_created = true;
    }
    return node;
}

/**
 * True if node already has an adjacency-list entry for neighbor_addr.
 */
static bool has_neighbor_entry(const struct topology_node *node, mixnet_address neighbor_addr)
{
    for (struct neighbor_list_node *cur = node->neighbors; cur != NULL; cur = cur->nxt)
    {
        if (cur->neighbor_addr == neighbor_addr)
        {
            return true;
        }
    }
    return false;
}

/**
 * Prepends a neighbor_list_node entry to node's adjacency list, unless
 * an entry for neighbor_addr is already present.
 */
bool add_neighbor_entry(struct topology_node *node, mixnet_address neighbor_addr, uint16_t cost)
{
    if (has_neighbor_entry(node, neighbor_addr))
    {
        return false; // neighbor_addr already in neighbor list
    }
    struct neighbor_list_node *entry = xcalloc(1, sizeof(struct neighbor_list_node));
    entry->neighbor_addr = neighbor_addr;
    entry->edge_cost = cost;
    entry->nxt = node->neighbors;
    node->neighbors = entry;
    return true;
}

bool add_topology_edge(struct topology_graph *graph, mixnet_address a, mixnet_address b, uint16_t cost)
{
    bool created_a = false;
    struct topology_node *node_a = get_or_create_topology_node(graph, a, &created_a);
    bool added_a = add_neighbor_entry(node_a, b, cost);

    // node_a may be dangling after this call if it triggered a realloc --
    // it isn't touched again, so that's fine.
    bool created_b = false;
    struct topology_node *node_b = get_or_create_topology_node(graph, b, &created_b);
    bool added_b = add_neighbor_entry(node_b, a, cost);

    return created_a || added_a || created_b || added_b;
}

bool update_graph(topology_graph *graph, mixnet_packet *packet)
{
    mixnet_packet_lsa *payload = (mixnet_packet_lsa *)packet->payload;
    mixnet_address my_adr = payload->node_address;

    bool graph_updated = false;
    for (size_t i = 0; i < payload->neighbor_count; i++)
    {
        mixnet_lsa_link_params nei_param = payload->links[i];
        bool edge_updated = add_topology_edge(graph, my_adr, nei_param.neighbor_mixaddr, nei_param.cost);
        graph_updated = graph_updated || edge_updated;
    }
    return graph_updated;
}

void free_topology_graph(struct topology_graph *graph)
{
    for (size_t i = 0; i < graph->count; i++)
    {
        struct neighbor_list_node *cur = graph->nodes[i].neighbors;
        while (cur != NULL)
        {
            struct neighbor_list_node *next = cur->nxt;
            free(cur);
            cur = next;
        }
    }
    free(graph->nodes);
    free(graph);
}