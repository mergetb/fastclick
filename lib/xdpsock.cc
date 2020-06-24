/*
 * xdpsock.{cc,hh} An express data path socket (XDP) object
 */

#include <click/xdpmanager.hh>
#include <click/xdpsock.hh>
#include <click/xdpinterface.hh>
#include <poll.h>

using std::make_shared;
using std::string;
using std::vector;

XDPSock::XDPSock(XDPInterfaceSP xfx, XDPUMEMSP xm, u32 queue_id, int xsks_map, bool trace)
: _xfx{xfx},
  _queue_id{queue_id},
  _trace{trace},
  _umem_mgr{xm},
  _xsks_map{xsks_map}
{
  configure_socket();
  printf("xdpsock %s is ready\n", xfx->dev().c_str());
}

void XDPSock::configure_socket()
{

    _xsk = static_cast<xsk_socket_info*>( calloc(1, sizeof(xsk_socket_info)) );
    if (_xsk == nullptr) {
        die("failed to allocate xsk", errno);
    }
    _xsk->umem = _umem_mgr->_umem;

    xsk_socket_config cfg{
        .rx_size = NUM_RX_DESCS,
            .tx_size = NUM_TX_DESCS,
            .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
            .xdp_flags = _xfx->xdp_flags(),
            .bind_flags = _xfx->bind_flags(),
    };

    int ret = xsk_socket__create(
            &_xsk->xsk,
            _xfx->dev().c_str(),
            _queue_id,
            _umem_mgr->_umem->umem,
            &_xsk->rx,
            &_xsk->tx,
            &cfg
            );
    if (ret) {
        die("failed to create xsk socket", ret);
    }

    ret = bpf_get_link_xdp_id(_xfx->ifindex(), &_prog_id, _xfx->xdp_flags());
    if (ret) {
        die("failed to get bpf program id", ret);
    }

    if(_trace) {
        printf("ingress UMEM: 0x%08x - 0x%08x\n", 0, NUM_RX_DESCS*FRAME_SIZE);
        printf("egress UMEM:  0x%08x - 0x%08x\n", 
                NUM_RX_DESCS*FRAME_SIZE, 
                NUM_RX_DESCS*FRAME_SIZE + NUM_TX_DESCS*FRAME_SIZE
              );
    }

    // initialize the fill queue addresses - the places in the UMEM where the
    // kernel will place received packets
    int n = NUM_RX_DESCS;
    u32 idx;
    ret = xsk_ring_prod__reserve(&_xsk->umem->fq, n, &idx);
    if (ret != n) die("failed to reserve fq descs", -ret);

    for(size_t i = 0; i < NUM_RX_DESCS; i++) {

        auto *addr = xsk_ring_prod__fill_addr(&_xsk->umem->fq, idx++);
        //*addr = i*FRAME_SIZE;
        *addr = umem_next() * FRAME_SIZE;

    }
    xsk_ring_prod__submit(&_xsk->umem->fq, NUM_RX_DESCS);

    _fd = xsk_socket__fd(_xsk->xsk);

    ret = bpf_map_update_elem(_xsks_map, &_queue_id, &_fd, 0);
    if (ret) die("failed to update bpf map elem", -ret);


}

void XDPSock::kick_tx()
{

  int ret = sendto(xsk_socket__fd(_xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
  if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
    return;

  die("failed to kick tx", ret);

}

void XDPSock::tx_complete()
{
    u32 idx_cq = 0;
    size_t ndescs;
    unsigned int rcvd;

    if (!_xsk->outstanding_tx) 
        return;

    if (xsk_ring_prod__needs_wakeup(&_xsk->tx)) 
        kick_tx();

    ndescs = _xsk->outstanding_tx < BATCH_SIZE 
        ? _xsk->outstanding_tx 
        : BATCH_SIZE;

    rcvd = xsk_ring_cons__peek(&_xsk->umem->cq, ndescs, &idx_cq);
    if (rcvd <= 0) {
        if (_trace)
            printf("tx: nothing transmitted\n");
        return;
    }

    if (_trace) {
        printf("tx: %d packets transmitted out %s\n", rcvd, _xfx->dev().c_str());
    }
    xsk_ring_cons__release(&_xsk->umem->cq, rcvd);
    _xsk->outstanding_tx -= rcvd;
    _xsk->tx_npkts += rcvd;
}

void XDPSock::fq_replenish() {

    u32 idx_fq = 0;
    size_t ndescs;
    int ret, i;

    ndescs = _xsk->outstanding_fq < BATCH_SIZE 
                ? _xsk->outstanding_fq 
                : BATCH_SIZE;

    ret = xsk_ring_prod__reserve(&_xsk->umem->fq, ndescs, &idx_fq);
    if (ret < 0)
        die("fq ring reserve failed", -ret);
    else if (ret == 0)
        return;

    if(_trace)
        printf("fq: replenish %d\n", ret);

    if (xsk_ring_prod__needs_wakeup(&_xsk->umem->fq)) {
	pollfd p = { .fd = _fd, .events = POLLIN };
        poll(&p, 1, 0);
    }

    for (i = 0; i < ret; i++)
        *xsk_ring_prod__fill_addr(&_xsk->umem->fq, idx_fq++) =
            umem_next() * FRAME_SIZE;

    xsk_ring_prod__submit(&_xsk->umem->fq, ret);
    _xsk->outstanding_fq -= ret;
}

void XDPSock::rx(PBuf &pb)
{
    unsigned int rcvd, i;
    u32 idx_rx = 0;
    int ret;

    pb.len = 0;

    rcvd = xsk_ring_cons__peek(&_xsk->rx, BATCH_SIZE, &idx_rx);
    if (rcvd < 0)
        die("rx ring peek failed %d", rcvd);
    else if (rcvd == 0)
        return;

    if (_trace) {
        printf("rx: forwarding from %s\n", _xfx->dev().c_str());
    }

    for (i = 0; i < rcvd; i++) {

        const struct xdp_desc *in;
        char *xsk_pkt;

        in = xsk_ring_cons__rx_desc(&_xsk->rx, idx_rx++);
        xsk_pkt = static_cast<char*>(xsk_umem__get_data(_xsk->umem->buffer, in->addr));

        WritablePacket *p =
            Packet::make(
                reinterpret_cast<unsigned char*>(xsk_pkt), 
                in->len,
                free_pkt, 
                xsk_pkt,
                FRAME_HEADROOM,
                FRAME_TAILROOM
            );
        p->timestamp_anno();
        if(_trace)
            printf("setqid=%d\n", _queue_id);
        p->set_anno_u32(8, _queue_id);
        if(_trace)
            printf("setaddr=%d\n", in->addr);
        p->set_anno_u64(12, in->addr);
        pb.pkts[i] = p;
    }
    pb.len = rcvd;
    xsk_ring_cons__release(&_xsk->rx, rcvd);
    _xsk->rx_npkts += rcvd;
    _xsk->outstanding_fq += rcvd;

    fq_replenish();
}

void XDPSock::tx(Packet *p)
{
    int ret;
    size_t i;
    u32 idx_tx = 0;
    
    tx_complete();

    //TODO batch interface
    ret = xsk_ring_prod__reserve(&_xsk->tx, 1, &idx_tx);
    while (ret != 1) {
	printf("fwd: re-reserve\n");
	if (ret < 0) die("tx reserve failed", -ret);
	if (xsk_ring_prod__needs_wakeup(&_xsk->tx)) kick_tx();
	ret = xsk_ring_prod__reserve(&_xsk->tx, 1, &idx_tx);
    }

    for (i = 0; i < ret; i++) {
	const struct xdp_desc *in;
	struct xdp_desc *out;

	// collect ingress/egress descriptors
	out = xsk_ring_prod__tx_desc(&_xsk->tx, idx_tx++);
	u32 addr = p->anno_u64(12);
	if(_trace)
	    printf("addr=%d\n", addr);

	if (_trace) {
	    printf("tx: addr=%lld len=%d\n", out->addr, addr);
	}

	// apply ingres as egress (forward)
	out->addr = addr;
	out->len  = p->length();
    }
    xsk_ring_prod__submit(&_xsk->tx, ret);
    _xsk->outstanding_tx += ret;

    kick_tx();
}

