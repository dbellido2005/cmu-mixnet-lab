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
#include "dijkstra.h"
#include "graph.h"

#include "helpers.h"
#include "packet.h"

#include <stdlib.h>
#include <string.h>

struct dijkstra_node create_dijkstra_node(mixnet_address addr, uint32_t cost,
                                          mixnet_address pred, bool is_visited)
{
    struct dijkstra_node node;
    node.address = addr;
    node.cost = cost;
    node.predecessor = pred;
    node.visited = is_visited;
    return node;
}

struct dijkstra_node *find_dijkstra_node(struct dijkstra_table *table, mixnet_address target)
{
    for (size_t i = 0; i < table->count; i++)
    {
        if (table->entries[i].address == target)
        {
            return &table->entries[i];
        }
    }
    return NULL;
}

/**
 * Grows table->entries if it's full, doubling capacity (starting at 4) --
 * same growth scheme as ensure_topology_capacity in graph.c.
 */
static void ensure_dijkstra_capacity(struct dijkstra_table *table)
{
    if (table->count < table->capacity)
    {
        return;
    }
    size_t new_capacity = (table->capacity == 0) ? 4 : table->capacity * 2;
    table->entries = xrealloc(table->entries, new_capacity * sizeof(struct dijkstra_node));
    table->capacity = new_capacity;
}

struct dijkstra_node *add_dijkstra_entry(struct dijkstra_table *table, mixnet_address addr,
                                         uint32_t cost, mixnet_address pred, bool is_visited)
{
    ensure_dijkstra_capacity(table);
    table->entries[table->count] = create_dijkstra_node(addr, cost, pred, is_visited);
    table->count++;
    return &table->entries[table->count - 1];
}

struct dijkstra_table *init_dijkstra_table(struct topology_graph *graph, mixnet_address self_addr)
{
    dijkstra_table *d_table = xcalloc(1, sizeof(struct dijkstra_table));
    add_dijkstra_entry(d_table, self_addr, 0, INVALID_MIXADDR, false);

    for (size_t i = 0; i < graph->count; i++)
    {
        topology_node node = graph->nodes[i];
        if (node.address != self_addr)
        {
            add_dijkstra_entry(d_table, node.address, UINT32_MAX, INVALID_MIXADDR, false);
        }
    }

    return d_table;
}

// Will return disconnected nodes with min_cost = UINT32_MAX
mixnet_address find_min_unexplored(dijkstra_table *table, bool *is_disconnected)
{
    uint32_t min_cost = UINT32_MAX;
    mixnet_address min_addr = INVALID_MIXADDR;
    for (size_t i = 0; i < table->count; i++)
    {
        dijkstra_node entry = table->entries[i];
        if (entry.visited == 0 && entry.cost <= min_cost)
        {
            min_cost = entry.cost;
            min_addr = entry.address;
        }
    }
    // flag that this node has no path to source (disconnected)
    if (min_cost == UINT32_MAX)
    {
        *is_disconnected = true;
    }
    return min_addr;
}

bool all_nodes_explored(dijkstra_table *table)
{
    for (size_t i = 0; i < table->count; i++)
    {
        dijkstra_node entry = table->entries[i];
        if (entry.visited == 0)
        {
            return false;
        }
    }
    return true;
}

// Fails if target_addr not in graph
topology_node *get_node(mixnet_address target_addr, topology_graph *graph, const struct mixnet_node_config c)
{
    for (size_t i = 0; i < graph->count; i++)
    {
        if (graph->nodes[i].address == target_addr)
        {
            return &graph->nodes[i];
        }
    }
    dlog(c, "[ERROR] get_node: address %u not found in topology graph", target_addr);
    exit(EXIT_FAILURE);
}

// Fails if target_addr not in graph
dijkstra_node *get_table_entry(mixnet_address target_addr, dijkstra_table *d_table, const struct mixnet_node_config c)
{
    for (size_t i = 0; i < d_table->count; i++)
    {
        if (d_table->entries[i].address == target_addr)
        {
            return &d_table->entries[i];
        }
    }
    dlog(c, "[ERROR] get_table_entry: address %u not found in dijkstra table", target_addr);
    exit(EXIT_FAILURE);
}

uint16_t get_route_len(mixnet_address src_addr, mixnet_address dst_addr, dijkstra_table *d_table,
                       const struct mixnet_node_config c)
{
    if (src_addr == dst_addr)
    {
        return 0;
    }
    uint16_t len = 0;
    dijkstra_node *entry = get_table_entry(dst_addr, d_table, c);
    mixnet_address pred_addr;
    while (entry->address != src_addr)
    {
        pred_addr = entry->predecessor;
        entry = get_table_entry(pred_addr, d_table, c);
        len++;
    }
    return len - 1;
}

void add_path_to_routing_header(dijkstra_table *d_table,
                                mixnet_packet_routing_header *routing_header,
                                const struct mixnet_node_config c)
{
    if (routing_header->src_address == routing_header->dst_address)
    {
        return;
    }
    uint16_t index = routing_header->route_length - 1;
    dijkstra_node *entry = get_table_entry(routing_header->dst_address, d_table, c);
    mixnet_address pred_addr;
    while (entry->address != routing_header->src_address)
    {
        pred_addr = entry->predecessor;
        entry = get_table_entry(pred_addr, d_table, c);
        if ((pred_addr != routing_header->src_address) && (pred_addr != routing_header->dst_address))
        {
            routing_header->route[index] = pred_addr;
            index--;
        }
    }
}

/**
 * Walks the dijkstra-predecessor chain from to_addr back to from_addr,
 * writing the intermediate hops (excluding both endpoints) into out[],
 * ending at out[end_index] and filling backward from there -- same
 * pattern as add_path_to_routing_header, but into a plain buffer
 * instead of a routing_header's route[]. Caller must know the hop
 * count ahead of time (via get_route_len(from_addr, to_addr, ...)) and
 * pass end_index = that count - 1.
 */
static void collect_hops_into(mixnet_address from_addr, mixnet_address to_addr,
                              dijkstra_table *d_table, const struct mixnet_node_config c,
                              mixnet_address *out, uint16_t end_index)
{
    if (from_addr == to_addr)
    {
        return;
    }
    uint16_t index = end_index;
    dijkstra_node *entry = get_table_entry(to_addr, d_table, c);
    mixnet_address pred_addr;
    while (entry->address != from_addr)
    {
        pred_addr = entry->predecessor;
        entry = get_table_entry(pred_addr, d_table, c);
        if ((pred_addr != from_addr) && (pred_addr != to_addr))
        {
            out[index] = pred_addr;
            index--;
        }
    }
}

/**
 * Attempts to build a randomized route from src_addr to dst_addr that
 * sometimes avoids the plain dijkstra shortest path:
 *
 * Scans backward from dst_addr along its dijkstra-predecessor chain.
 * At each node "current" visited this way, looks (in random order) for
 * a neighbor Y other than current's own dijkstra predecessor, such
 * that Y's own predecessor chain back to src_addr does NOT pass
 * through current (avoids the route looping back through a node it's
 * already past). If such a Y is found, the route becomes:
 *   (shortest path src_addr -> Y) , Y , current , <nodes already
 *   walked backward from current down to (but excluding) dst_addr>
 * If current is dst_addr itself, there is no trailing suffix and
 * current itself isn't added (it's the destination, not an
 * intermediate hop).
 *
 * If no node anywhere on the path -- all the way back to src_addr --
 * has such a neighbor, returns false: the caller should fall back to
 * the plain dijkstra route.
 *
 * On success, returns true, allocates *out_route (caller must free)
 * holding the ordered intermediate hop addresses, and sets *out_len.
 */
bool compute_random_route(mixnet_address src_addr, mixnet_address dst_addr,
                          topology_graph *graph, dijkstra_table *d_table,
                          const struct mixnet_node_config c,
                          mixnet_address **out_route, uint16_t *out_len)
{
    if (src_addr == dst_addr)
    {
        return false;
    }

    // backward_walk[0] = dst_addr, backward_walk[1] = dst_addr's dijkstra
    // predecessor, etc., walking toward src_addr.
    mixnet_address *backward_walk = xcalloc(d_table->count, sizeof(mixnet_address));
    uint16_t backward_count = 0;
    backward_walk[backward_count++] = dst_addr;

    mixnet_address current = dst_addr;
    while (current != src_addr)
    {
        dijkstra_node *current_entry = get_table_entry(current, d_table, c);
        mixnet_address dijkstra_pred = current_entry->predecessor;
        topology_node *current_node = get_node(current, graph, c);

        // gather current's neighbors excluding its own dijkstra predecessor
        uint16_t num_candidates = 0;
        for (neighbor_list_node *nei = current_node->neighbors; nei != NULL; nei = nei->nxt)
        {
            if (nei->neighbor_addr != dijkstra_pred)
            {
                num_candidates++;
            }
        }

        if (num_candidates > 0)
        {
            mixnet_address *candidates = xcalloc(num_candidates, sizeof(mixnet_address));
            uint16_t idx = 0;
            for (neighbor_list_node *nei = current_node->neighbors; nei != NULL; nei = nei->nxt)
            {
                if (nei->neighbor_addr != dijkstra_pred)
                {
                    candidates[idx++] = nei->neighbor_addr;
                }
            }

            // try candidates in random order until one's path back to
            // src_addr doesn't loop back through current
            while (num_candidates > 0)
            {
                uint16_t pick = rand() % num_candidates;
                mixnet_address y_addr = candidates[pick];

                bool loops_through_current = false;
                mixnet_address walk_addr = y_addr;
                while (walk_addr != src_addr)
                {
                    if (walk_addr == current)
                    {
                        loops_through_current = true;
                        break;
                    }
                    dijkstra_node *walk_entry = get_table_entry(walk_addr, d_table, c);
                    walk_addr = walk_entry->predecessor;
                }

                if (!loops_through_current)
                {
                    // found a valid detour point -- assemble the full route
                    uint16_t prefix_len = get_route_len(src_addr, y_addr, d_table, c);
                    uint16_t suffix_len = backward_count - 1; // excludes backward_walk[0] = dst_addr
                    uint16_t total_len = prefix_len + 1 + suffix_len;

                    mixnet_address *route = xcalloc(total_len, sizeof(mixnet_address));

                    // prefix: src_addr -> y_addr intermediates, forward order
                    if (prefix_len > 0)
                    {
                        collect_hops_into(src_addr, y_addr, d_table, c, route, prefix_len - 1);
                    }

                    // y_addr itself
                    route[prefix_len] = y_addr;

                    // current, then the already-walked suffix down to (not
                    // including) dst_addr, in forward order
                    for (uint16_t i = 0; i < suffix_len; i++)
                    {
                        route[prefix_len + 1 + i] = backward_walk[backward_count - 1 - i];
                    }

                    free(candidates);
                    free(backward_walk);
                    *out_route = route;
                    *out_len = total_len;
                    return true;
                }

                // discard this candidate, try another
                candidates[pick] = candidates[num_candidates - 1];
                num_candidates--;
            }
            free(candidates);
        }

        // no valid candidate at `current` -- step back to its predecessor
        current = dijkstra_pred;
        backward_walk[backward_count++] = current;
    }

    free(backward_walk);
    return false; // no detour found anywhere; caller should use plain dijkstra
}

void add_routing_header(dijkstra_table *d_table, mixnet_packet *packet, bool is_data_packet,
                        topology_graph *graph, const struct mixnet_node_config c, bool is_random)
{
    mixnet_packet_routing_header *routing_header = (mixnet_packet_routing_header *)&(packet->payload);

    // compute route len -- randomized if the caller rolled for it (per
    // c.do_random_routing being on for this node) and a valid detour was
    // found, otherwise the plain dijkstra route
    mixnet_address *random_route = NULL;
    uint16_t route_len;
    bool used_random_route = false;

    if (is_random)
    {
        used_random_route = compute_random_route(routing_header->src_address, routing_header->dst_address,
                                                  graph, d_table, c, &random_route, &route_len);
    }

    if (!used_random_route)
    {
        route_len = get_route_len(routing_header->src_address, routing_header->dst_address, d_table, c);
    }

    routing_header->route_length = route_len;

    // move packet data to give space for the route array
    if (is_data_packet)
    {
        uint16_t data_size = packet->total_size - sizeof(mixnet_packet) - sizeof(mixnet_packet_routing_header);
        char *data_ptr = (char *)routing_header + sizeof(mixnet_packet_routing_header);
        char *data_ptr_dest = data_ptr + route_len * sizeof(mixnet_address);
        memmove(data_ptr_dest, data_ptr, data_size);
    }

    // grow total_size to account for the newly-added route array
    packet->total_size = packet->total_size + route_len * sizeof(mixnet_address);

    // add to routing_header
    if (used_random_route)
    {
        memcpy(routing_header->route, random_route, route_len * sizeof(mixnet_address));
        free(random_route);
    }
    else
    {
        add_path_to_routing_header(d_table, routing_header, c);
    }
}

void reverse_route(mixnet_packet_routing_header *routing_header)
{
    mixnet_address tmp_addr = routing_header->src_address;
    routing_header->src_address = routing_header->dst_address;
    routing_header->dst_address = tmp_addr;

    if (routing_header->route_length > 0)
    {
        uint16_t left = 0;
        uint16_t right = routing_header->route_length - 1;
        while (left < right)
        {
            mixnet_address tmp = routing_header->route[left];
            routing_header->route[left] = routing_header->route[right];
            routing_header->route[right] = tmp;
            left++;
            right--;
        }
    }

    routing_header->hop_index = 0;
}

dijkstra_table *compute_dijkstra(topology_graph *graph, mixnet_address self_addr, const struct mixnet_node_config c)
{
    dijkstra_table *d_table = init_dijkstra_table(graph, self_addr);

    // Run Dijkstra algorithm
    mixnet_address cur_addr; // DANGER: do not use without initializing
    topology_node *cur_node;
    dijkstra_node *cur_entry;

    while (!all_nodes_explored(d_table))
    {
        // select next node
        bool is_disconnected = false;
        cur_addr = find_min_unexplored(d_table, &is_disconnected);

        // mark as visited if disconnected (avoids infinite loop)
        if (is_disconnected)
        {
            cur_entry = get_table_entry(cur_addr, d_table, c);
            cur_entry->visited = 1;
        }
        else
        {
            cur_node = get_node(cur_addr, graph, c);
            cur_entry = get_table_entry(cur_addr, d_table, c);
            cur_entry->visited = 1;

            // update neighbor best paths
            for (neighbor_list_node *nei_param = cur_node->neighbors; nei_param != NULL; nei_param = nei_param->nxt)
            {
                dijkstra_node *nei_entry = get_table_entry(nei_param->neighbor_addr, d_table, c);
                if (nei_entry->visited == 0)
                {
                    uint32_t cur_cost = cur_entry->cost + nei_param->edge_cost;
                    if (cur_cost < nei_entry->cost)
                    {
                        nei_entry->cost = cur_cost;
                        nei_entry->predecessor = cur_addr;
                    }
                }
            }
        }
    }

    return d_table;
}

void free_dijkstra_table(struct dijkstra_table *table)
{
    free(table->entries);
    free(table);
}
