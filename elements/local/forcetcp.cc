/*
 * ForceTCP.{cc,hh} -- sets the TCP header checksum
 * Robert Morris
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology.
 *
 * This software is being provided by the copyright holders under the GNU
 * General Public License, either version 2 or, at your discretion, any later
 * version. For more information, see the `COPYRIGHT' file in the source
 * distribution.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include "forcetcp.hh"
#include "glue.hh"
#include "error.hh"
#include "click_ip.h"
#include "click_tcp.h"

ForceTCP::ForceTCP()
{
  add_input();
  add_output();
  _count = 0;
}

ForceTCP::~ForceTCP()
{
}

ForceTCP *
ForceTCP::clone() const
{
  return new ForceTCP();
}

Packet *
ForceTCP::simple_action(Packet *p_in)
{
  WritablePacket *p = p_in->uniqueify();
  click_ip *ip = p->ip_header();
  unsigned plen = p->length() - p->ip_header_offset();
  unsigned hlen, ilen, oisum, off;
  char itmp[9];
  click_tcp *th;

  if (!ip || plen < sizeof(click_ip))
    goto bad;

  hlen = ip->ip_hl << 2;
  if (hlen < sizeof(click_ip) || hlen > plen)
    goto bad;

  ilen = ntohs(ip->ip_len);
  if(ilen > plen || ilen < hlen + sizeof(click_tcp))
    goto bad;

  th = (click_tcp *) (((char *)ip) + hlen);

  off = th->th_off << 2;
  if(off < sizeof(click_tcp) || off > (ilen - hlen)){
    th->th_off = (ilen - hlen) >> 2;
  }

  if((_count & 7) < 2){
    th->th_dport = htons(80);
  } else if((_count & 7) == 3){
    th->th_dport = htons(random() % 1024);
  }
  _count++;

  memcpy(itmp, ip, 9);
  memset(ip, '\0', 9);
  oisum = ip->ip_sum;
  ip->ip_sum = 0;
  ip->ip_len = htons(ilen - hlen);

  th->th_sum = 0;
  th->th_sum = in_cksum((unsigned char *)ip, ilen);

  memcpy(ip, itmp, 9);
  ip->ip_sum = oisum;
  ip->ip_len = htons(ilen);

  return p;

 bad:
  click_chatter("ForceTCP: bad lengths");
  p->kill();
  return(0);
}

EXPORT_ELEMENT(ForceTCP)
