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
#include "helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <sys/time.h>

static FILE *get_log_file(const struct mixnet_node_config c)
{
    static FILE *log_file = NULL;
    if (log_file == NULL)
    {
        const char *log_dir = getenv("MIXNET_LOG_DIR");
        char path[512];
        snprintf(path, sizeof(path), "%s/node_%u.log",
                 (log_dir != NULL) ? log_dir : ".", c.node_addr);
        log_file = fopen(path, "w");
        if (log_file == NULL)
        {
            log_file = stderr;
        }
    }
    return log_file;
}

void dlog(const struct mixnet_node_config c, const char *fmt, ...)
{
    FILE *f = get_log_file(c);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(f, "[%ld.%06ld] node=%-3u ",
            (long)tv.tv_sec, (long)tv.tv_usec, c.node_addr);

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fprintf(f, "\n");
    fflush(f);
}

void *xcalloc(size_t num, size_t size)
{
    void *ptr = calloc(num, size);
    if (ptr == NULL)
    {
        fprintf(stderr, "[ERROR] xcalloc: calloc(%zu, %zu) returned NULL\n", num, size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    if (new_ptr == NULL)
    {
        fprintf(stderr, "[ERROR] xrealloc: realloc(%p, %zu) returned NULL\n", ptr, size);
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

void print_stp(const char *label, const spanning_tree *stp, uint8_t num_neighbors, const struct mixnet_node_config c)
{
    dlog(c, "[STP] %s", label ? label : "");
    dlog(c, "  Root Address: %u", stp->root_addr);
    dlog(c, "  Next Hop (adr): %u", stp->next_hop_adr);
    dlog(c, "  Path Length: %u", stp->path_len);

    char ports_buf[256] = {0};
    size_t off = 0;
    for (uint8_t i = 0; i < num_neighbors && off < sizeof(ports_buf); i++)
    {
        off += snprintf(ports_buf + off, sizeof(ports_buf) - off,
                        "%u:%s ", i, stp->open_ports[i] ? "OPEN" : "BLOCKED");
    }
    dlog(c, "  Open Ports: %s", ports_buf);

    char neighbors_buf[256] = {0};
    off = 0;
    for (uint8_t i = 0; i < num_neighbors && off < sizeof(neighbors_buf); i++)
    {
        off += snprintf(neighbors_buf + off, sizeof(neighbors_buf) - off,
                        "port%u->node%u ", i, stp->port_to_addr[i]);
    }
    dlog(c, "  Neighbors: %s", neighbors_buf);
}

mixnet_packet *deep_copy_packet(mixnet_packet *src)
{
    assert(src != NULL);
    mixnet_packet *dst = xcalloc(1, src->total_size);
    memcpy(dst, src, src->total_size);
    return dst;
}
