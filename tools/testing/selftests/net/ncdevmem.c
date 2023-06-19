// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#define __EXPORTED_HEADERS__

#include <linux/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#define __iovec_defined
#include <fcntl.h>
#include <malloc.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <linux/memfd.h>
#include <linux/if.h>
#include <linux/dma-buf.h>
#include <linux/udmabuf.h>
#include <libmnl/libmnl.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/netdev.h>
#include <time.h>

#include "netdev-user.h"
#include <ynl.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define TEST_PREFIX "ncdevmem"
#define NUM_PAGES 16000

#ifndef MSG_SOCK_DEVMEM
#define MSG_SOCK_DEVMEM 0x2000000
#endif

/*
 * tcpdevmem netcat. Works similarly to netcat but does device memory TCP
 * instead of regular TCP. Uses udmabuf to mock a dmabuf provider.
 *
 * Usage:
 *
 * * Without validation:
 *
 *	On server:
 *	ncdevmem -s <server IP> -c <client IP> -f eth1 -n 0000:06:00.0 -l \
 *		-p 5201
 *
 *	On client:
 *	ncdevmem -s <server IP> -c <client IP> -f eth1 -n 0000:06:00.0 -p 5201
 *
 * * With Validation:
 *	On server:
 *	ncdevmem -s <server IP> -c <client IP> -l -f eth1 -n 0000:06:00.0 \
 *		-p 5202 -v 1
 *
 *	On client:
 *	ncdevmem -s <server IP> -c <client IP> -f eth1 -n 0000:06:00.0 -p 5202 \
 *		-v 100000
 *
 * Note this is compatible with regular netcat. i.e. the sender or receiver can
 * be replaced with regular netcat to test the RX or TX path in isolation.
 */

static char *server_ip = "192.168.1.4";
static char *client_ip = "192.168.1.2";
static char *port = "5201";
static size_t do_validation;
static int queue_num = 15;
static char *ifname = "eth1";
static char *nic_pci_addr = "0000:06:00.0";
static unsigned int iterations;

void print_bytes(void *ptr, size_t size)
{
	unsigned char *p = ptr;
	int i;
	for (i = 0; i < size; i++) {
		printf("%02hhX ", p[i]);
	}
	printf("\n");
}

void print_nonzero_bytes(void *ptr, size_t size)
{
	unsigned char *p = ptr;
	unsigned int i;
	for (i = 0; i < size; i++) {
		if (p[i])
			printf("%c", p[i]);
	}
	printf("\n");
}

void initialize_validation(void *line, size_t size)
{
	static unsigned char seed = 1;
	unsigned char *ptr = line;
	for (size_t i = 0; i < size; i++) {
		ptr[i] = seed;
		seed++;
		if (seed == 254)
			seed = 0;
	}
}

void validate_buffer(void *line, size_t size)
{
	static unsigned char seed = 1;
	int errors = 0;

	unsigned char *ptr = line;
	for (size_t i = 0; i < size; i++) {
		if (ptr[i] != seed) {
			fprintf(stderr,
				"Failed validation: expected=%u, "
				"actual=%u, index=%lu\n",
				seed, ptr[i], i);
			errors++;
			if (errors > 20)
				exit(1);
		}
		seed++;
		if (seed == do_validation)
			seed = 0;
	}

	fprintf(stdout, "Validated buffer\n");
}

/* Triggers a driver reset...
 *
 * The proper way to do this is probably 'ethtool --reset', but I don't have
 * that supported on my current test bed. I resort to changing this
 * configuration in the driver which also causes a driver reset...
 */
static void reset_flow_steering(void)
{
	char command[256];
	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command), "sudo ethtool -K %s ntuple off",
		 "eth1");
	system(command);

	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command), "sudo ethtool -K %s ntuple on",
		 "eth1");
	system(command);
}

static void configure_flow_steering(void)
{
	char command[256];
	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command),
		 "sudo ethtool -N %s flow-type tcp4 src-ip %s dst-ip %s "
		 "src-port %s dst-port %s queue %d",
		 ifname, client_ip, server_ip, port, port, queue_num);
	system(command);
}

/* Triggers a device reset, which causes the dmabuf pages binding to take
 * effect. A better and more generic way to do this may be ethtool --reset.
 */
static void trigger_device_reset(void)
{
	char command[256];
	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command),
		 "sudo ethtool --set-priv-flags %s enable-header-split off",
		 ifname);
	system(command);

	memset(command, 0, sizeof(command));
	snprintf(command, sizeof(command),
		 "sudo ethtool --set-priv-flags %s enable-header-split on",
		 ifname);
	system(command);
}

static int bind_rx_queue(unsigned int ifindex, unsigned int dmabuf_fd,
			 __u32 *queue_idx, unsigned int n_queue_index,
			 struct ynl_sock **ys)
{
	struct ynl_error yerr;

	struct netdev_bind_rx_req *req = NULL;
	int ret = 0;

	*ys = ynl_sock_create(&ynl_netdev_family, &yerr);
	if (!*ys) {
		fprintf(stderr, "YNL: %s\n", yerr.msg);
		return -1;
	}

	if (ynl_subscribe(*ys, "mgmt"))
		goto err_close;

	req = netdev_bind_rx_req_alloc();
	netdev_bind_rx_req_set_ifindex(req, ifindex);
	netdev_bind_rx_req_set_dmabuf_fd(req, dmabuf_fd);
	__netdev_bind_rx_req_set_queues(req, queue_idx, n_queue_index);

	ret = netdev_bind_rx(*ys, req);
	if (!ret) {
		perror("netdev_bind_rx");
		goto err_close;
	}

	netdev_bind_rx_req_free(req);

	return 0;

err_close:
	fprintf(stderr, "YNL failed: %s\n", (*ys)->err.msg);
	netdev_bind_rx_req_free(req);
	ynl_sock_destroy(*ys);
	return -1;
}

static void create_udmabuf(int *devfd, int *memfd, int *buf, size_t dmabuf_size)
{
	struct udmabuf_create create;
	int ret;

	*devfd = open("/dev/udmabuf", O_RDWR);
	if (*devfd < 0) {
		fprintf(stderr,
			"%s: [skip,no-udmabuf: Unable to access DMA "
			"buffer device file]\n",
			TEST_PREFIX);
		exit(70);
	}

	*memfd = memfd_create("udmabuf-test", MFD_ALLOW_SEALING);
	if (*memfd < 0) {
		printf("%s: [skip,no-memfd]\n", TEST_PREFIX);
		exit(72);
	}

	ret = fcntl(*memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0) {
		printf("%s: [skip,fcntl-add-seals]\n", TEST_PREFIX);
		exit(73);
	}

	ret = ftruncate(*memfd, dmabuf_size);
	if (ret == -1) {
		printf("%s: [FAIL,memfd-truncate]\n", TEST_PREFIX);
		exit(74);
	}

	memset(&create, 0, sizeof(create));

	create.memfd = *memfd;
	create.offset = 0;
	create.size = dmabuf_size;
	*buf = ioctl(*devfd, UDMABUF_CREATE, &create);
	if (*buf < 0) {
		printf("%s: [FAIL, create udmabuf]\n", TEST_PREFIX);
		exit(75);
	}
}

int do_server(void)
{
	int devfd, memfd, buf, ret;
	size_t dmabuf_size;
	struct ynl_sock *ys;

	dmabuf_size = getpagesize() * NUM_PAGES;

	create_udmabuf(&devfd, &memfd, &buf, dmabuf_size);

	__u32 *queue_idx = malloc(sizeof(__u32) * 2);

	queue_idx[0] = 14;
	queue_idx[1] = 15;
	if (bind_rx_queue(3 /* index for eth1 */, buf, queue_idx, 2, &ys)) {
		fprintf(stderr, "Failed to bind\n");
		exit(1);
	}

	char *buf_mem = NULL;
	buf_mem = mmap(NULL, dmabuf_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		       buf, 0);
	if (buf_mem == MAP_FAILED) {
		perror("mmap()");
		exit(1);
	}

	/* Need to trigger the NIC to reallocate its RX pages, otherwise the
	 * bind doesn't take effect.
	 */
	trigger_device_reset();

	sleep(1);

	reset_flow_steering();
	configure_flow_steering();

	struct sockaddr_in server_sin;
	server_sin.sin_family = AF_INET;
	server_sin.sin_port = htons(atoi(port));

	ret = inet_pton(server_sin.sin_family, server_ip, &server_sin.sin_addr);
	if (socket < 0) {
		printf("%s: [FAIL, create socket]\n", TEST_PREFIX);
		exit(79);
	}

	int socket_fd = socket(server_sin.sin_family, SOCK_STREAM, 0);
	if (socket < 0) {
		printf("%s: [FAIL, create socket]\n", TEST_PREFIX);
		exit(76);
	}

	int opt = 1;
	ret = setsockopt(socket_fd, SOL_SOCKET,
			 SO_REUSEADDR | SO_REUSEPORT | SO_ZEROCOPY, &opt,
			 sizeof(opt));
	if (ret) {
		printf("%s: [FAIL, set sock opt]: %s\n", TEST_PREFIX,
		       strerror(errno));
		exit(76);
	}

	printf("binding to address %s:%d\n", server_ip,
	       ntohs(server_sin.sin_port));

	ret = bind(socket_fd, &server_sin, sizeof(server_sin));
	if (ret) {
		printf("%s: [FAIL, bind]: %s\n", TEST_PREFIX, strerror(errno));
		exit(76);
	}

	ret = listen(socket_fd, 1);
	if (ret) {
		printf("%s: [FAIL, listen]: %s\n", TEST_PREFIX,
		       strerror(errno));
		exit(76);
	}

	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	char buffer[256];

	inet_ntop(server_sin.sin_family, &server_sin.sin_addr, buffer,
		  sizeof(buffer));
	printf("Waiting or connection on %s:%d\n", buffer,
	       ntohs(server_sin.sin_port));
	int client_fd = accept(socket_fd, &client_addr, &client_addr_len);

	inet_ntop(client_addr.sin_family, &client_addr.sin_addr, buffer,
		  sizeof(buffer));
	printf("Got connection from %s:%d\n", buffer,
	       ntohs(client_addr.sin_port));

	char iobuf[819200];
	char ctrl_data[sizeof(int) * 20000];

	size_t total_received = 0;
	size_t i = 0;
	size_t page_aligned_frags = 0;
	size_t non_page_aligned_frags = 0;
	while (1) {
		bool is_devmem = false;
		printf("\n\n");

		struct msghdr msg = { 0 };
		struct iovec iov = { .iov_base = iobuf,
				     .iov_len = sizeof(iobuf) };
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl_data;
		msg.msg_controllen = sizeof(ctrl_data);
		ssize_t ret = recvmsg(client_fd, &msg, MSG_SOCK_DEVMEM);
		printf("recvmsg ret=%ld\n", ret);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			continue;
		}
		if (ret < 0) {
			perror("recvmsg");
			continue;
		}
		if (ret == 0) {
			printf("client exited\n");
			goto cleanup;
		}

		i++;
		struct cmsghdr *cm = NULL;
		struct cmsg_devmem *cmsg_devmem = NULL;
		for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			if (cm->cmsg_level != SOL_SOCKET ||
			    (cm->cmsg_type != SCM_DEVMEM_OFFSET &&
			     cm->cmsg_type != SCM_DEVMEM_HEADER)) {
				fprintf(stdout, "skipping non-devmem cmsg\n");
				continue;
			}

			cmsg_devmem = (struct cmsg_devmem *)CMSG_DATA(cm);
			is_devmem = true;

			if (cm->cmsg_type == SCM_DEVMEM_HEADER) {
				/* TODO: process data copied from skb's linear
				 * buffer.
				 */
				fprintf(stdout,
					"SCM_DEVMEM_HEADER. "
					"cmsg_devmem->frag_size=%u\n",
					cmsg_devmem->frag_size);

				continue;
			}

			struct devmemtoken token = { cmsg_devmem->frag_token,
						     1 };

			total_received += cmsg_devmem->frag_size;
			printf("received frag_page=%llu, in_page_offset=%llu,"
			       " frag_offset=%llu, frag_size=%u, token=%u"
			       " total_received=%lu\n",
			       cmsg_devmem->frag_offset >> PAGE_SHIFT,
			       cmsg_devmem->frag_offset % PAGE_SIZE,
			       cmsg_devmem->frag_offset, cmsg_devmem->frag_size,
			       cmsg_devmem->frag_token, total_received);

			if (cmsg_devmem->frag_size % PAGE_SIZE)
				non_page_aligned_frags++;
			else
				page_aligned_frags++;

			struct dma_buf_sync sync = { 0 };
			sync.flags = DMA_BUF_SYNC_READ | DMA_BUF_SYNC_START;
			ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync);

			if (do_validation)
				validate_buffer(
					((unsigned char *)buf_mem) +
						cmsg_devmem->frag_offset,
					cmsg_devmem->frag_size);
			else
				print_nonzero_bytes(
					((unsigned char *)buf_mem) +
						cmsg_devmem->frag_offset,
					cmsg_devmem->frag_size);

			sync.flags = DMA_BUF_SYNC_READ | DMA_BUF_SYNC_END;
			ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync);

			ret = setsockopt(client_fd, SOL_SOCKET,
					 SO_DEVMEM_DONTNEED, &token,
					 sizeof(token));
			if (ret != 1) {
				perror("SO_DEVMEM_DONTNEED not enough tokens");
				exit(1);
			}
		}
		if (!is_devmem)
			printf("flow steering error\n");

		printf("total_received=%lu\n", total_received);
	}

	fprintf(stdout, "%s: ok\n", TEST_PREFIX);

	fprintf(stdout, "page_aligned_frags=%lu, non_page_aligned_frags=%lu\n",
		page_aligned_frags, non_page_aligned_frags);

	fprintf(stdout, "page_aligned_frags=%lu, non_page_aligned_frags=%lu\n",
		page_aligned_frags, non_page_aligned_frags);

cleanup:

	munmap(buf_mem, dmabuf_size);
	close(client_fd);
	close(socket_fd);
	close(buf);
	close(memfd);
	close(devfd);
	ynl_sock_destroy(ys);
	trigger_device_reset();

	return 0;
}

int main(int argc, char *argv[])
{
	int is_server = 0, opt;

	while ((opt = getopt(argc, argv, "ls:c:p:v:q:f:n:i:")) != -1) {
		switch (opt) {
		case 'l':
			is_server = 1;
			break;
		case 's':
			server_ip = optarg;
			break;
		case 'c':
			client_ip = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'v':
			do_validation = atoll(optarg);
			break;
		case 'q':
			queue_num = atoi(optarg);
			break;
		case 'f':
			ifname = optarg;
			break;
		case 'n':
			nic_pci_addr = optarg;
			break;
		case 'i':
			iterations = atoll(optarg);
			break;
		case '?':
			printf("unknown option: %c\n", optopt);
			break;
		}
	}

	for (; optind < argc; optind++) {
		printf("extra arguments: %s\n", argv[optind]);
	}

	if (is_server)
		return do_server();

	return 0;
}
