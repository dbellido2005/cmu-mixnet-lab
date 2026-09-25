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
#ifndef MIXNET_HELPERS_H_
#define MIXNET_HELPERS_H_

#include "config.h"
#include "node.h"
#include "packet.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Per-node debug logging. Node processes are separate OS processes whose
     * stdout would otherwise interleave unreadably across a multi-node test;
     * this instead writes one timestamped log file per node (node_<addr>.log,
     * under $MIXNET_LOG_DIR if set, else the current directory), so a failing
     * run's event order can be reconstructed afterward instead of read live
     * off an interleaved terminal.
     */
    void dlog(const struct mixnet_node_config c, const char *fmt, ...);

    void *xcalloc(size_t num, size_t size);
    void *xrealloc(void *ptr, size_t size);

    void print_stp(const char *label, const spanning_tree *stp, uint8_t num_neighbors, const struct mixnet_node_config c);

    /**
     * Heap-allocates a copy of src, sized to src->total_size.
     */
    mixnet_packet *deep_copy_packet(mixnet_packet *src);

#ifdef __cplusplus
}
#endif

#endif // MIXNET_HELPERS_H_
