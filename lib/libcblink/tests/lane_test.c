/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The control lane: notifications of a CBL_MCF_CONTROL group and a
 * CBL_SF_CONTROL stream, sent while a bulk transfer (a dump, a push
 * stream) fills the association.  Over SCTP they keep their order and
 * are not held behind the bulk; over TCP they keep their order.
 */

#include <stdatomic.h>
#include <time.h>

#include "cbl_net_test.h"

enum { L_BULK = 1, L_FEED, L_CTL };
enum { LA_SEQ = 1, LA_AT, LA_PAD };
enum { G_CTL, G_PLAIN };

#define	NOTES		40		/* of each kind */
#define	NOTE_GAP_US	5000
#define	PART		(64 * 1024)
#define	BOUND_US	(100 * 1000)	/* control: at most this late */
/* The client takes a part a millisecond (64 MB/s), its socket's room
 * small: the path, not the sender, sets the pace, as on a WAN. */
#define	SLOW_US		1000
#define	RCVBUF		(256 * 1024)

static unsigned char pad[PART];

static uint64_t
us_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

/* The server's side. */
struct srv {
	atomic_bool	 stop;		/* the bulk ends */
	atomic_bool	 bulk_on;	/* its first part went */
	cbl_stream	*ctl;		/* the control stream, once accepted */
	atomic_bool	 ctl_up;
	cbl_family	*fam;
};

static int
bulk_dumpit(cbl_req *req, const cbl_msg *msg __unused,
    struct cbl_dump_state *st, void *arg)
{
	struct srv *sv = arg;
	cbl_msg *item;
	int error;

	if (sv->stop)
		return (0);
	if ((error = cbl_req_dump_item(req, &item)) != 0)
		return (error);
	t_put_uint(item, LA_SEQ, st->pos[0]++);
	t_put_bytes(item, LA_PAD, pad, sizeof(pad));
	sv->bulk_on = true;
	if ((error = cbl_req_send(req, item)) != 0)
		return (error);
	return (EAGAIN);
}

static void
feed_pump(cbl_stream *s, struct srv *sv)
{
	cbl_msg *m;
	int error;

	while (!sv->stop) {
		if (cbl_stream_msg_new(s, &m) != 0)
			return;
		t_put_bytes(m, LA_PAD, pad, sizeof(pad));
		if ((error = cbl_stream_send(s, m)) == EAGAIN) {
			cbl_msg_free(m);
			return;
		}
		if (error != 0)
			return;
		sv->bulk_on = true;
	}
	(void)cbl_stream_half_close(s);
}

static void
feed_writable(cbl_stream *s, size_t credit __unused, void *arg)
{

	feed_pump(s, arg);
}

static void
srv_sclose(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg __unused)
{
}

static const struct cbl_stream_cbs feed_cbs = {
	.on_writable = feed_writable,
	.on_close = srv_sclose,
};

static int
feed_open(cbl_req *req __unused, const cbl_msg *msg __unused, cbl_stream *s,
    void *arg)
{
	int error;

	if ((error = cbl_stream_accept(s, NULL, 0, &feed_cbs, arg)) != 0)
		return (error);
	feed_pump(s, arg);
	return (0);
}

static const struct cbl_stream_cbs ctl_cbs = {
	.on_close = srv_sclose,
};

static int
ctl_open(cbl_req *req __unused, const cbl_msg *msg __unused, cbl_stream *s,
    void *arg)
{
	struct srv *sv = arg;
	int error;

	if ((error = cbl_stream_accept(s, NULL, CBL_SF_CONTROL, &ctl_cbs,
	    sv)) != 0)
		return (error);
	cbl_stream_ref(s);
	sv->ctl = s;
	sv->ctl_up = true;
	return (0);
}

static const struct cbl_op l_ops[] = {
	{ .cmd = L_BULK, .name = "bulk", .flags = CBL_OPF_DUMP,
	  .dumpit = bulk_dumpit },
	{ .cmd = L_FEED, .name = "feed", .flags = CBL_OPF_PUSH,
	  .stream_open = feed_open },
	{ .cmd = L_CTL, .name = "ctl", .flags = CBL_OPF_PUSH,
	  .stream_open = ctl_open },
};
static const struct cbl_mcgrp l_grps[] = {
	{ .name = "ctl", .flags = CBL_MCF_CONTROL },
	{ .name = "plain" },
};
static const struct cbl_family_def l_def = {
	.abi = CBL_FAMILY_ABI, .name = "lanes", .version = 1,
	.ops = l_ops, .nops = nitems(l_ops),
	.mcgrps = l_grps, .nmcgrps = nitems(l_grps),
};

/* What one kind of notification did at the client. */
struct kind {
	const char	*name;
	int		 n;
	uint64_t	 next;
	bool		 in_order;
	uint64_t	 max_us, sum_us;
};

struct cli {
	struct kind	 ctl, plain, sctl;
	atomic_bool	 bulk_done;
	uint64_t	 bulk_bytes;
	uint64_t	 bulk_end_us;
	cbl_stream	*feed, *cs;
	atomic_int	 opened;
};

static void
kind_rec(struct kind *k, const cbl_msg *m)
{
	uint64_t seq = UINT64_MAX, at = 0, now = us_now(), d;

	(void)t_get_uint(m, LA_SEQ, &seq);
	(void)t_get_uint(m, LA_AT, &at);
	if (seq != k->next)
		k->in_order = false;
	k->next = seq + 1;
	d = now - at;
	k->sum_us += d;
	if (d > k->max_us)
		k->max_us = d;
	k->n++;
}

static void
ctl_note(cbl_conn *conn __unused, cbl_msg *msg, void *arg)
{
	struct cli *c = arg;

	kind_rec(&c->ctl, msg);
}

static void
plain_note(cbl_conn *conn __unused, cbl_msg *msg, void *arg)
{
	struct cli *c = arg;

	kind_rec(&c->plain, msg);
}

static void
bulk_cb(cbl_conn *conn __unused, cbl_msg *reply, bool final,
    int error __unused, void *arg)
{
	struct cli *c = arg;
	const void *p;
	size_t len;

	if (reply != NULL && t_get_bytes(reply, LA_PAD, &p, &len)) {
		c->bulk_bytes += len;
		usleep(SLOW_US);
	}
	if (final) {
		c->bulk_end_us = us_now();
		c->bulk_done = true;
	}
}

static void
cli_open(cbl_stream *s __unused, cbl_msg *accept __unused, int error,
    void *arg)
{
	struct cli *c = arg;

	ATF_REQUIRE_EQ(0, error);
	c->opened++;
}

static void
feed_data(cbl_stream *s __unused, cbl_msg *data, void *arg)
{
	struct cli *c = arg;
	const void *p;
	size_t len;

	if (t_get_bytes(data, LA_PAD, &p, &len)) {
		c->bulk_bytes += len;
		usleep(SLOW_US);
	}
}

static void
feed_end(cbl_stream *s __unused, int code __unused, const char *text __unused,
    void *arg)
{
	struct cli *c = arg;

	c->bulk_end_us = us_now();
	c->bulk_done = true;
}

static const struct cbl_stream_cbs cfeed_cbs = {
	.on_open = cli_open,
	.on_data = feed_data,
	.on_close = feed_end,
};

static void
sctl_data(cbl_stream *s __unused, cbl_msg *data, void *arg)
{
	struct cli *c = arg;

	kind_rec(&c->sctl, data);
}

static void
sctl_close(cbl_stream *s __unused, int code __unused,
    const char *text __unused, void *arg __unused)
{
}

static const struct cbl_stream_cbs csctl_cbs = {
	.on_open = cli_open,
	.on_data = sctl_data,
	.on_close = sctl_close,
};

struct fx {
	cbl_ctx		*sctx, *cctx;
	cbl_loop	*loop;
	cbl_listener	*l;
	pthread_t	 thr;
	struct srv	 sv;
	char		 uri[64];
	cbl_conn	*c;
};

static void *
fx_loop(void *arg)
{

	(void)cbl_loop_run(arg);
	return (NULL);
}

static void
fx_setup(struct fx *f, const char *proto)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	socklen_t len = sizeof(ss);
	char base[64];
	int fd;

	if (strcmp(proto, "sctp") == 0) {
		if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1)
			atf_tc_skip("SCTP is not available: %s",
			    strerror(errno));
		close(fd);
	}
	memset(f, 0, sizeof(*f));
	memset(pad, 0x5A, sizeof(pad));
	f->sctx = test_ctx();
	f->cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_family_register(f->sctx, &l_def, &f->sv,
	    &f->sv.fam));
	ATF_REQUIRE_EQ(0, cbl_loop_new(f->sctx, &f->loop));
	snprintf(base, sizeof(base), "%s://127.0.0.1:0", proto);
	ATF_REQUIRE_EQ(0, cbl_listener_new(f->sctx, base, CBL_PLAINTEXT,
	    &f->l));
	ATF_REQUIRE_EQ(0, cbl_listener_start(f->l, f->loop));
	ATF_REQUIRE_EQ(0, cbl_listener_addr(f->l, &ss, &len));
	snprintf(f->uri, sizeof(f->uri), "%s://127.0.0.1:%u", proto,
	    ntohs(sin->sin_port));
	ATF_REQUIRE_EQ(0, pthread_create(&f->thr, NULL, fx_loop, f->loop));
	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->uri, CBL_PLAINTEXT, &f->c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f->c));
	(void)setsockopt(cbl_conn_fd(f->c), SOL_SOCKET, SO_RCVBUF,
	    &(int){ RCVBUF }, sizeof(int));
}

static void
fx_teardown(struct fx *f)
{

	cbl_conn_free(f->c);
	cbl_loop_stop(f->loop);
	pthread_join(f->thr, NULL);
	if (f->sv.ctl != NULL)
		cbl_stream_rele(f->sv.ctl);
	cbl_listener_free(f->l);
	cbl_loop_free(f->loop);
	ATF_REQUIRE_EQ(0, cbl_family_unregister(f->sv.fam));
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
}

/* Drive the client until done() or ms pass. */
static void
drive(struct fx *f, bool (*done)(struct cli *), struct cli *c, int ms)
{
	uint64_t end = us_now() + (uint64_t)ms * 1000;
	struct pollfd pfd;
	int events, timeout;

	while (!done(c) && us_now() < end) {
		(void)cbl_conn_interest(f->c, &events, &timeout);
		pfd.fd = cbl_conn_fd(f->c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		pfd.revents = 0;
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(f->c,
		    ((pfd.revents & (POLLIN | POLLHUP)) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
}

static bool
opened2(struct cli *c)
{

	return (c->opened >= 2);
}

/* The server's notifier: each kind NOTES times, NOTE_GAP_US apart. */
struct notifier {
	struct fx	*f;
	bool		 stream;
	pthread_t	 thr;
};

static void
note_put(cbl_msg *m, uint64_t seq)
{

	t_put_uint(m, LA_SEQ, seq);
	t_put_uint(m, LA_AT, us_now());
}

static void *
notifier(void *arg)
{
	struct notifier *n = arg;
	struct srv *sv = &n->f->sv;
	cbl_msg *m;

	while (!sv->bulk_on)
		usleep(1000);
	/* The bulk well under way: the queues full. */
	usleep(100000);
	for (uint64_t i = 0; i < NOTES; i++) {
		ATF_REQUIRE_EQ(0, cbl_notify_msg_new(sv->fam, L_BULK, &m));
		note_put(m, i);
		ATF_REQUIRE_EQ(0, cbl_notify(sv->fam, G_CTL, m));
		ATF_REQUIRE_EQ(0, cbl_notify_msg_new(sv->fam, L_BULK, &m));
		note_put(m, i);
		ATF_REQUIRE_EQ(0, cbl_notify(sv->fam, G_PLAIN, m));
		if (n->stream) {
			ATF_REQUIRE_EQ(0, cbl_stream_msg_new(sv->ctl, &m));
			note_put(m, i);
			ATF_REQUIRE_EQ(0, cbl_stream_send(sv->ctl, m));
		}
		usleep(NOTE_GAP_US);
	}
	usleep(100000);
	sv->stop = true;
	return (NULL);
}

static bool
all_in(struct cli *c)
{

	return (c->bulk_done && c->ctl.n == NOTES && c->plain.n == NOTES &&
	    (c->cs == NULL || c->sctl.n == NOTES));
}

static void
kind_say(const char *proto, const char *bulk, const struct kind *k)
{

	fprintf(stderr, "%s %s %-6s: %d in order %s, delay mean %.2f ms, "
	    "max %.2f ms\n", proto, bulk, k->name, k->n, k->in_order ? "yes" :
	    "no", k->n > 0 ? (double)k->sum_us / k->n / 1000 : 0,
	    (double)k->max_us / 1000);
}

static void
cli_init(struct cli *c)
{

	memset(c, 0, sizeof(*c));
	c->ctl.name = "ctl";
	c->plain.name = "plain";
	c->sctl.name = "stream";
	c->ctl.in_order = c->plain.in_order = c->sctl.in_order = true;
}

/*
 * Run: the client subscribes to both groups (and opens the control
 * stream), starts the bulk, and takes everything as it comes.
 */
static void
run(const char *proto, bool dump, bool control_bound)
{
	struct notifier n;
	struct fx f;
	struct cli c;
	cbl_sub *s1, *s2;
	cbl_msg *m;
	uint64_t t0;

	fx_setup(&f, proto);
	cli_init(&c);
	ATF_REQUIRE_EQ(0, cbl_subscribe(f.c, "lanes", "ctl", ctl_note, &c,
	    &s1));
	ATF_REQUIRE_EQ(0, cbl_subscribe(f.c, "lanes", "plain", plain_note, &c,
	    &s2));
	ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, cbl_family_id(f.sv.fam), L_CTL,
	    0, &m));
	ATF_REQUIRE_EQ(0, cbl_stream_open(f.c, m, CBL_SF_PUSH, &csctl_cbs, &c,
	    &c.cs));
	if (dump) {
		c.opened++;
		ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, cbl_family_id(f.sv.fam),
		    L_BULK, CBL_F_DUMP, &m));
		ATF_REQUIRE_EQ(0, cbl_request_async(f.c, m, bulk_cb, &c));
	} else {
		ATF_REQUIRE_EQ(0, cbl_msg_new(f.cctx, cbl_family_id(f.sv.fam),
		    L_FEED, 0, &m));
		ATF_REQUIRE_EQ(0, cbl_msg_set_window(m, 8 * 1024 * 1024));
		ATF_REQUIRE_EQ(0, cbl_stream_open(f.c, m, CBL_SF_PUSH,
		    &cfeed_cbs, &c, &c.feed));
	}
	drive(&f, opened2, &c, 5000);
	ATF_REQUIRE(c.opened >= 2);
	while (!f.sv.ctl_up)
		usleep(1000);
	n.f = &f;
	n.stream = true;
	t0 = us_now();
	ATF_REQUIRE_EQ(0, pthread_create(&n.thr, NULL, notifier, &n));
	drive(&f, all_in, &c, 60000);
	pthread_join(n.thr, NULL);
	fprintf(stderr, "%s %s: %.1f MiB in %.2f s\n", proto,
	    dump ? "dump" : "stream", (double)c.bulk_bytes / 1048576,
	    (double)(c.bulk_end_us - t0) / 1000000);
	kind_say(proto, dump ? "dump" : "stream", &c.ctl);
	kind_say(proto, dump ? "dump" : "stream", &c.sctl);
	kind_say(proto, dump ? "dump" : "stream", &c.plain);
	ATF_REQUIRE(c.bulk_done);
	ATF_REQUIRE_EQ(NOTES, c.ctl.n);
	ATF_REQUIRE_EQ(NOTES, c.sctl.n);
	ATF_REQUIRE_EQ(NOTES, c.plain.n);
	ATF_REQUIRE(c.ctl.in_order);
	ATF_REQUIRE(c.sctl.in_order);
	ATF_REQUIRE(c.plain.in_order);
	if (control_bound) {
		ATF_REQUIRE_MSG(c.ctl.max_us < BOUND_US, "a control "
		    "notification %.1f ms late", (double)c.ctl.max_us / 1000);
		ATF_REQUIRE_MSG(c.sctl.max_us < BOUND_US, "a control stream's "
		    "data %.1f ms late", (double)c.sctl.max_us / 1000);
	}
	(void)cbl_unsubscribe(s1);
	(void)cbl_unsubscribe(s2);
	fx_teardown(&f);
}

ATF_TC_WITHOUT_HEAD(sctp_dump);
ATF_TC_BODY(sctp_dump, tc)
{

	run("sctp", true, true);
}

ATF_TC_WITHOUT_HEAD(sctp_stream);
ATF_TC_BODY(sctp_stream, tc)
{

	run("sctp", false, true);
}

/* TCP: one byte stream, the order kept, no bound promised. */
ATF_TC_WITHOUT_HEAD(tcp_dump);
ATF_TC_BODY(tcp_dump, tc)
{

	run("tcp", true, false);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sctp_dump);
	ATF_TP_ADD_TC(tp, sctp_stream);
	ATF_TP_ADD_TC(tp, tcp_dump);
	return (atf_no_error());
}
