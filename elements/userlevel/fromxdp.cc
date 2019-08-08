/*
 * fromxdp.{cc,hh} reads network packets from a linux netdev via XDP
 *
 * Ryan Goodfellow
 *
 * Copyright (c) 2019 mergetb.org
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include "fromxdp.hh"
#include <click/args.hh>
#include <click/error.hh>

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/mman.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
}

CLICK_DECLS

static void free_pkt(unsigned char *, size_t, void *pktmbuf)
{
   //TODO, possibly no need for anything ans umem_fill_to_kernel_ex churns the
   //ring?
}

bool FromXDP::run_task(Task *t) 
{

  struct xdp_desc descs[BATCH_SIZE];
  unsigned int rcvd = xq_deq(&_xsk->rx, descs, BATCH_SIZE);
  printf("recvd: %u\n", rcvd);
  if (!rcvd)
    return false;

  for (unsigned int i = 0; i < rcvd; i++) {
    char *pkt = (char*)xq_get_data(_xsk, descs[i].addr);
    hex_dump(pkt, descs[i].len, descs[i].addr);

    //TODO totally untested
    WritablePacket *p = Packet::make(
        (unsigned char*)pkt,
        descs[i].len,
        free_pkt,
        pkt,
        FRAME_HEADROOM,
        FRAME_TAILROOM
    );
    output(0).push(p);
  }

  _xsk->rx_npkts += rcvd;

  umem_fill_to_kernel_ex(&_xsk->umem->fq, descs, rcvd);

  t->fast_reschedule();

  return true;

}

CLICK_ENDDECLS

EXPORT_ELEMENT(FromXDP)
