/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: a byte stream as a peer sends it on an accepted connection
 * (a unix socketpair, so no TLS between), read by the connection itself
 * in integration mode: the receive ring and the frames cut out of it
 * (headers split across reads, a frame larger than the ring, a bad
 * header's frame skipped), then each frame dispatched as the server does
 * (the control family's rpcs, subscriptions, and a family of an echo, a
 * dump and a stream that echoes its data) or taken as a reply, a stream
 * frame or a notification.  What the connection answers is read and
 * dropped; the stream ends with EOF, and the connection is freed.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cblink.h"
#include "cbl_schema.h"

int	LLVMFuzzerInitialize(int *argc, char ***argv);
int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define	FUZZ_MAXLEN	(64 * 1024)
#define	ROUNDS		256		/* of cbl_conn_process(), at most */

/* The family corpus/conn names: the first registered (2), cmds 3 to 5. */
#define	F_ECHO		3
#define	F_LIST		4
#define	F_FEED		5
#define	A_VAL		7
#define	A_N		8

static cbl_ctx *ctx;

static int
echo_doit(cbl_req *req, const cbl_msg *msg, void *arg __unused)
{
	const void *p;
	cbl_msg *rsp;
	size_t len;
	int error;

	if ((error = cbl_req_reply_new(req, 0, &rsp)) != 0)
		return (error);
	if (cbl_msg_sid_raw(msg, A_VAL, &p, &len) == 0 &&
	    (error = cbl_msg_put_sid_raw(rsp, A_VAL, p, len)) != 0) {
		cbl_msg_free(rsp);
		return (error);
	}
	return (cbl_req_send(req, rsp));
}

/* A[N] items (a one-byte uint: at most 23), one per call. */
static int
list_dumpit(cbl_req *req, const cbl_msg *msg, struct cbl_dump_state *st,
    void *arg __unused)
{
	static const uint8_t val[] = { 0x44, 'i', 't', 'e', 'm' };
	const uint8_t *p;
	uint64_t n = 3;
	cbl_msg *item;
	size_t len;
	int error;

	if (cbl_msg_sid_raw(msg, A_N, (const void **)&p, &len) == 0) {
		if (len != 1 || p[0] > 23) {
			cbl_req_set_err(req, "bad count", NULL, 0, -1);
			return (EINVAL);
		}
		n = p[0];
	}
	if (st->pos[0] >= n)
		return (0);
	if ((error = cbl_req_dump_item(req, &item)) != 0)
		return (error);
	if ((error = cbl_msg_put_sid_raw(item, A_VAL, val, sizeof(val))) !=
	    0) {
		cbl_msg_free(item);
		return (error);
	}
	if ((error = cbl_req_send(req, item)) != 0)
		return (error);
	st->pos[0]++;
	return (EAGAIN);
}

/* Each data frame's value sent back, while there is credit; the library
 * frees data, and gives credit back for it. */
static void
feed_data(cbl_stream *s, cbl_msg *data, void *arg __unused)
{
	const void *p;
	cbl_msg *m;
	size_t len;

	if (cbl_msg_sid_raw(data, A_VAL, &p, &len) != 0 ||
	    cbl_stream_msg_new(s, &m) != 0)
		return;
	if (cbl_msg_put_sid_raw(m, A_VAL, p, len) != 0) {
		cbl_msg_free(m);
		return;
	}
	if (cbl_stream_send(s, m) == EAGAIN)
		cbl_msg_free(m);
}

static void
feed_hclose(cbl_stream *s, void *arg __unused)
{

	(void)cbl_stream_half_close(s);
}

static const struct cbl_stream_cbs feed_cbs = {
	.on_data = feed_data,
	.on_hclose = feed_hclose,
};

static int
feed_open(cbl_req *req __unused, const cbl_msg *msg __unused, cbl_stream *s,
    void *arg __unused)
{

	return (cbl_stream_accept(s, NULL, 0, &feed_cbs, NULL));
}

static const struct cbl_op ops[] = {
	{ .cmd = F_ECHO, .name = "echo", .flags = CBL_OPF_DO,
	  .doit = echo_doit },
	{ .cmd = F_LIST, .name = "list", .flags = CBL_OPF_DO | CBL_OPF_DUMP,
	  .doit = echo_doit, .dumpit = list_dumpit },
	{ .cmd = F_FEED, .name = "feed", .flags = CBL_OPF_STREAM,
	  .stream_open = feed_open },
};

static const struct cbl_mcgrp grps[] = {
	{ .name = "events" },
};

static const struct cbl_family_def def = {
	.abi = CBL_FAMILY_ABI,
	.name = "fuzz",
	.version = 1,
	.ops = ops,
	.nops = sizeof(ops) / sizeof(ops[0]),
	.mcgrps = grps,
	.nmcgrps = 1,
};

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{
	cbl_family *fam;

	if (cbl_ctx_new(&ctx) != 0 ||
	    cbl_family_register(ctx, &def, NULL, &fam) != 0 ||
	    cbl_family_id(fam) != 2)
		abort();
	return (0);
}

/* What the connection wrote, read and dropped. */
static void
drain(int fd)
{
	char buf[16384];

	while (read(fd, buf, sizeof(buf)) > 0)
		;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int sv[2], bufsz = 2 * FUZZ_MAXLEN;
	cbl_conn *conn;
	ssize_t n;

	if (size > FUZZ_MAXLEN)
		return (0);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		abort();
	(void)setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
	(void)setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
	if (size > 0 && (n = write(sv[1], data, size)) != (ssize_t)size)
		abort();
	(void)shutdown(sv[1], SHUT_WR);
	if (fcntl(sv[1], F_SETFL, O_NONBLOCK) == -1)
		abort();
	if (cbl_conn_new_fd(ctx, sv[0], CBL_CF_ACCEPT, &conn) != 0)
		abort();
	for (int i = 0; i < ROUNDS && cbl_conn_is_open(conn); i++) {
		(void)cbl_conn_process(conn, CBL_EV_READ | CBL_EV_WRITE);
		drain(sv[1]);
	}
	cbl_conn_free(conn);
	close(sv[1]);
	return (0);
}
