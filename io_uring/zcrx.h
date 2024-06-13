// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>
#include <linux/io_uring/net.h>
#include <linux/skbuff.h>
#include <net/page_pool/types.h>

#define IO_ZC_MAX_IFQ_SOCKETS		16
#define IO_ZC_IFQ_IDX_OFFSET		16
#define IO_ZC_IFQ_IDX_MASK		((1U << IO_ZC_IFQ_IDX_OFFSET) - 1)

#define IO_ZC_RX_UREF			0x10000
#define IO_ZC_RX_KREF_MASK		(IO_ZC_RX_UREF - 1)

struct io_zcrx_area {
	struct net_iov_area	nia;
	struct io_zcrx_ifq	*ifq;

	u16			area_id;
	struct page		**pages;

	/* freelist */
	spinlock_t		freelist_lock ____cacheline_aligned_in_smp;
	u32			free_count;
	u32			*freelist;
};

struct io_zcrx_ifq {
	struct io_ring_ctx		*ctx;
	struct net_device		*dev;
	struct io_zcrx_area		*area;
	struct page_pool		*pp;

	struct io_uring			*rq_ring;
	struct io_uring_rbuf_rqe 	*rqes;
	u32				rq_entries;
	u32				cached_rq_head;

	unsigned short			n_rqe_pages;
	struct page			**rqe_pages;

	u32				if_rxq;

	unsigned			nr_sockets;
	struct file			*sockets[IO_ZC_MAX_IFQ_SOCKETS];
};

#if defined(CONFIG_PAGE_POOL)
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			 struct io_uring_zcrx_ifq_reg __user *arg);
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx);
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx);
int io_register_zcrx_sock(struct io_ring_ctx *ctx,
			  struct io_uring_zcrx_sock_reg __user *arg);
int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags,
		 unsigned int issue_flags);
#else
static inline int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_ifq_reg __user *arg)
{
	return -EOPNOTSUPP;
}
static inline void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline int io_register_zcrx_sock(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_sock_reg __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
				struct socket *sock, unsigned int flags,
				unsigned int issue_flags)
{
	return -EOPNOTSUPP;
}
#endif

int io_recvzc(struct io_kiocb *req, unsigned int issue_flags);
int io_recvzc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

#endif
