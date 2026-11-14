/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * NACM (RFC 8341) over a connection: a server of nacmdemo's data, rpcs
 * and notifications and of ietf-netconf-acm's rules, and a family of its
 * own whose ops ask NACM, each request made for the user the client says
 * (cbl_msg_set_user()), as the server's fn takes it.
 *
 * The rules: alice in group admin, which may do anything; bob and dave
 * in group limited, which may not ping, and may change an item named
 * after them; carol in no group.  Read and exec are permitted by
 * default, write is not; what nacmdemo marks nacm:default-deny-all or
 * -write is held back but by the admin's rule.  Some cases put rules of
 * their own in the limited group's place (custom()).
 */

#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbl_net_test.h"
#include "ynacmh.h"

static const struct cbl_ynode *n_data, *n_locked, *n_ping, *n_echo, *n_reboot;
static const struct cbl_ynode *n_event, *n_alarm, *n_nacm, *n_item, *n_reset;
static const struct cbl_ynode *n_changed;

/* data, locked and nacm, kept as YANG-CBOR. */
static struct kept {
	const struct cbl_ynode	*n;
	struct cbl_ybuf		 b;
	bool			 have;
} kept[3];

/* Who a request saying nobody is: NULL, the recovery session. */
static const char *dflt_user;

static const struct cbl_ynode *
top(const char *mod, const char *name)
{

	for (uint32_t i = 0; i < ynacmh_schema.nmod; i++) {
		const struct cbl_ymodule *m = ynacmh_schema.mod[i];

		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t j = 0; j < m->ntop; j++)
			if (strcmp(m->top[j]->name, name) == 0)
				return (m->top[j]);
	}
	atf_tc_fail("no %s:%s", mod, name);
}

static uint64_t
child_sid(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]->sid);
	atf_tc_fail("%s has no %s", n->name, name);
}

static const struct cbl_ynode *
io(const struct cbl_ynode *rpc, int kind)
{

	for (uint32_t i = 0; i < rpc->nchild; i++)
		if (rpc->child[i]->kind == kind)
			return (rpc->child[i]);
	atf_tc_fail("%s has no %s", rpc->name, kind == CBL_YN_INPUT ? "input" :
	    "output");
}

static int
kget(int i, void *data, cbl_yarena *a)
{

	if (!kept[i].have)
		return (0);
	return (cbl_ydecode_member(kept[i].n, kept[i].b.p, kept[i].b.len, data,
	    a, CBL_YD_STRICT, NULL, 0));
}

static int
kset(int i, const void *after)
{

	cbl_ybuf_free(&kept[i].b);
	memset(&kept[i].b, 0, sizeof(kept[i].b));
	kept[i].have = false;
	if (!cbl_ymember_present(kept[i].n, after))
		return (0);
	if (cbl_yencode_member(kept[i].n, after, &kept[i].b) != 0)
		return (EIO);
	kept[i].have = true;
	return (0);
}

static int
data_get(cbl_req *req, void *data, cbl_yarena *a)
{

	(void)req;
	return (kget(0, data, a));
}

static int
data_edit(cbl_req *req, const void *before, const void *after)
{

	(void)req;
	(void)before;
	return (kset(0, after));
}

static int
locked_get(cbl_req *req, void *data, cbl_yarena *a)
{

	(void)req;
	return (kget(1, data, a));
}

static int
locked_edit(cbl_req *req, const void *before, const void *after)
{

	(void)req;
	(void)before;
	return (kset(1, after));
}

static int
nacm_get(cbl_req *req, void *data, cbl_yarena *a)
{

	(void)req;
	return (kget(2, data, a));
}

static int
nacm_edit(cbl_req *req, const void *before, const void *after)
{

	(void)req;
	(void)before;
	return (kset(2, after));
}

static int
ok_rpc(cbl_req *req, const void *in, void *out, cbl_yarena *a)
{
	struct nacmdemo_echo_output *o = out;

	(void)req;
	(void)in;
	(void)a;
	o->has_ok = true;
	o->ok = true;
	return (0);
}

/* The server's: a user said is taken, but mallory's; none, dflt_user. */
static int
user_fn(const cbl_peer *peer, const char *said, char *name, size_t len,
    bool *recovery, void *arg)
{

	(void)peer;
	(void)arg;
	if (said != NULL) {
		if (strcmp(said, "mallory") == 0)
			return (EACCES);
		strlcpy(name, said, len);
	} else if (dflt_user != NULL)
		strlcpy(name, dflt_user, len);
	else
		*recovery = true;
	return (0);
}

/* A family of its own: look, any user's; change, nacm:default-deny-all's. */
static int
op_doit(cbl_req *req, const cbl_msg *msg, void *arg)
{

	(void)req;
	(void)msg;
	(void)arg;
	return (0);
}

static const struct cbl_op nd_ops[] = {
	{ .cmd = 1, .flags = CBL_OPF_DO | CBL_OPF_NACM, .name = "look",
	    .doit = op_doit },
	{ .cmd = 2, .flags = CBL_OPF_DO | CBL_OPF_NACM | CBL_OPF_DENY,
	    .name = "change", .doit = op_doit },
};

static const struct cbl_family_def nd_def = {
	.abi = CBL_FAMILY_ABI,
	.name = "nd",
	.version = 1,
	.ops = nd_ops,
	.nops = nitems(nd_ops),
};

static int
reset_action(cbl_req *req, const struct cbl_bytes *target, const void *in,
    void *out, cbl_yarena *a)
{
	struct nacmdemo_data_item_reset_output *o = out;

	(void)req;
	(void)target;
	(void)in;
	(void)a;
	o->has_ok = true;
	o->ok = true;
	return (0);
}

static struct cbl_yhandler handlers[7];
static struct cbl_yserver server = { .schema = &ynacmh_schema };

static int
hcmp(const void *a, const void *b)
{
	const struct cbl_yhandler *x = a, *y = b;

	return ((x->sid > y->sid) - (x->sid < y->sid));
}

/* access-operations' bits, by position: create, read, update, delete,
 * exec. */
static uint8_t opbits[4];

/* The rules, into kept[2]; enable as given. */
static void
rules(bool enable)
{
	static const char *const admins[] = { "alice" };
	static const char *const limited[] = { "bob", "dave" };
	static const struct ietf_netconf_acm_nacm_groups_group g[] = {
		{ .name = "admin", .user_name = { 1, admins } },
		{ .name = "limited", .user_name = { 2, limited } },
	};
	static const struct ietf_netconf_acm_nacm_groups gs = {
		.group = { 2, g } };
	static const struct ietf_netconf_acm_nacm_rule_list_group ga[] = {
		{ .which = 1, .v.m1 = "admin" } };
	static const struct ietf_netconf_acm_nacm_rule_list_group gl[] = {
		{ .which = 1, .v.m1 = "limited" } };
	struct ietf_netconf_acm_nacm_rule_list_rule ra[] = {
		{ .name = "permit-all", .has_module_name = true,
		    .module_name = { .which = 0, .v.m0 = "*" },
		    .has_access_operations = true,
		    .access_operations = { .which = 0, .v.m0 = "*" },
		    .has_action = true,
		    .action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT },
	};
	struct ietf_netconf_acm_nacm_rule_list_rule rl[] = {
		{ .name = "deny-ping", .has_module_name = true,
		    .module_name = { .which = 1, .v.m1 = "nacmdemo" },
		    .rule_type =
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_RULE_TYPE_PROTOCOL_OPERATION,
		    .has_rpc_name = true,
		    .rpc_name = { .which = 1, .v.m1 = "ping" },
		    .has_access_operations = true,
		    .access_operations = { .which = 1, .v.m1 = { &opbits[0],
		    1 } },
		    .has_action = true,
		    .action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_DENY },
		{ .name = "own-item", .has_module_name = true,
		    .module_name = { .which = 1, .v.m1 = "nacmdemo" },
		    .rule_type =
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_RULE_TYPE_DATA_NODE,
		    .path = "/nacmdemo:data/nacmdemo:item[nacmdemo:name=$USER]",
		    .has_access_operations = true,
		    .access_operations = { .which = 1, .v.m1 = { &opbits[1],
		    1 } },
		    .has_action = true,
		    .action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT },
	};
	struct ietf_netconf_acm_nacm_rule_list l[] = {
		{ .name = "admin-acl", .group = { 1, ga },
		    .rule = { nitems(ra), ra } },
		{ .name = "limited-acl", .group = { 1, gl },
		    .rule = { nitems(rl), rl } },
	};
	struct ietf_netconf_acm_nacm nacm = {
		.has_enable_nacm = true, .enable_nacm = enable,
		.groups = &gs, .rule_list = { nitems(l), l },
	};
	struct ietf_netconf_acm d = { .nacm = &nacm };

	opbits[0] = 1u << 4;				/* exec */
	opbits[1] = (1u << 0) | (1u << 2) | (1u << 3);	/* create update delete */
	ATF_REQUIRE_EQ(0, kset(2, &d));
}

/* The data first there: public, secret, carol's item. */
static void
data0(void)
{
	static const struct nacmdemo_data_item items[] = {
		{ .name = "carol", .note = "c" } };
	struct nacmdemo_data dd = { .public = "hi", .secret = "s3",
	    .item = { 1, items } };
	struct nacmdemo d = { .data = &dd };

	ATF_REQUIRE_EQ(0, kset(0, &d));
}

struct fixture {
	cbl_ctx			*sctx;
	cbl_ctx			*cctx;
	struct test_server	 ts;
	cbl_conn		*c;
	cbl_family		*fam;
};

static void
setup(struct fixture *f)
{

	n_data = top("nacmdemo", "data");
	n_locked = top("nacmdemo", "locked");
	n_ping = top("nacmdemo", "ping");
	n_echo = top("nacmdemo", "echo");
	n_reboot = top("nacmdemo", "reboot");
	n_event = top("nacmdemo", "event");
	n_alarm = top("nacmdemo", "alarm");
	n_nacm = top("ietf-netconf-acm", "nacm");
	handlers[0] = (struct cbl_yhandler){ n_data->sid, data_get, data_edit,
	    NULL, NULL };
	handlers[1] = (struct cbl_yhandler){ n_locked->sid, locked_get,
	    locked_edit, NULL, NULL };
	handlers[2] = (struct cbl_yhandler){ n_ping->sid, NULL, NULL, ok_rpc,
	    NULL };
	handlers[3] = (struct cbl_yhandler){ n_echo->sid, NULL, NULL, ok_rpc,
	    NULL };
	handlers[4] = (struct cbl_yhandler){ n_reboot->sid, NULL, NULL, ok_rpc,
	    NULL };
	handlers[5] = (struct cbl_yhandler){ n_nacm->sid, nacm_get, nacm_edit,
	    NULL, NULL };
	n_item = NULL;
	for (uint32_t i = 0; i < n_data->nchild; i++)
		if (strcmp(n_data->child[i]->name, "item") == 0)
			n_item = n_data->child[i];
	ATF_REQUIRE(n_item != NULL);
	for (uint32_t i = 0; i < n_item->nchild; i++) {
		if (strcmp(n_item->child[i]->name, "reset") == 0)
			n_reset = n_item->child[i];
		if (strcmp(n_item->child[i]->name, "changed") == 0)
			n_changed = n_item->child[i];
	}
	handlers[6] = (struct cbl_yhandler){ n_reset->sid, NULL, NULL, NULL,
	    reset_action };
	qsort(handlers, nitems(handlers), sizeof(handlers[0]), hcmp);
	server.nhandler = nitems(handlers);
	server.handler = handlers;
	kept[0].n = n_data;
	kept[1].n = n_locked;
	kept[2].n = n_nacm;
	dflt_user = NULL;
	data0();
	rules(true);

	f->sctx = test_ctx();
	f->cctx = test_ctx();
	ATF_REQUIRE_EQ(0, cbl_yserver_add(f->sctx, &server, NULL));
	ATF_REQUIRE_EQ(0, cbl_ctx_set_user(f->sctx, user_fn, NULL));
	ATF_REQUIRE_EQ(0, cbl_family_register(f->sctx, &nd_def, NULL,
	    &f->fam));
	test_server_start(&f->ts, f->sctx, "tcp://127.0.0.1:0",
	    CBL_PLAINTEXT);
	ATF_REQUIRE_EQ(0, cbl_conn_new(f->cctx, f->ts.uri, CBL_PLAINTEXT,
	    &f->c));
	ATF_REQUIRE_EQ(0, cbl_conn_connect(f->c));
}

static void
teardown(struct fixture *f)
{

	cbl_conn_free(f->c);
	test_server_stop(&f->ts);
	cbl_ctx_free(f->sctx);
	cbl_ctx_free(f->cctx);
	for (size_t i = 0; i < nitems(kept); i++) {
		cbl_ybuf_free(&kept[i].b);
		memset(&kept[i].b, 0, sizeof(kept[i].b));
		kept[i].have = false;
	}
}

/* A request of family 1 for user (NULL: none said). */
static cbl_msg *
req(struct fixture *f, uint16_t cmd, const char *user)
{
	cbl_msg *m;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, CBL_YANG_FAMILY, cmd, 0, &m));
	if (user != NULL)
		ATF_REQUIRE_EQ(0, cbl_msg_set_user(m, user));
	return (m);
}

/* What user reads of data: whether public and secret are there, how
 * many items; the request's errno. */
static int
get_data(struct fixture *f, const char *user, bool *pub, bool *sec,
    size_t *items)
{
	struct nacmdemo d = { 0 };
	cbl_msg *m = req(f, CBL_YCMD_GET, user), *r = NULL;
	cbl_yarena *a;
	int error;

	*pub = *sec = false;
	*items = 0;
	ATF_REQUIRE_EQ(0, cbl_msg_put_yget(m, &n_data->sid, 1));
	if ((error = cbl_request(f->c, m, &r, 5000)) != 0) {
		cbl_msg_free(r);
		return (error);
	}
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	if (cbl_msg_ydecode_member(r, n_data, &d, a, CBL_YD_STRICT, NULL,
	    0) == 0 && d.data != NULL) {
		*pub = d.data->public != NULL;
		*sec = d.data->secret != NULL;
		*items = d.data->item.n;
	}
	cbl_yarena_free(a);
	cbl_msg_free(r);
	return (0);
}

/* EDIT data, as user: public as given, the secret kept, items those
 * given; the errno, and the error's node. */
static int
edit_data(struct fixture *f, const char *user, const char *public,
    const struct nacmdemo_data_item *items, size_t n, uint64_t *at)
{
	struct nacmdemo_data dd = { .public = public, .secret = "s3",
	    .item = { n, items } };
	struct nacmdemo d = { .data = &dd };
	cbl_msg *m = req(f, CBL_YCMD_EDIT, user), *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_data, &d));
	error = cbl_request(f->c, m, &r, 5000);
	if (at != NULL)
		*at = r != NULL ? cbl_msg_err_sid(r) : 0;
	cbl_msg_free(r);
	return (error);
}

static int
edit_locked(struct fixture *f, const char *user, int32_t x)
{
	struct nacmdemo_locked l = { .has_x = true, .x = x };
	struct nacmdemo d = { .locked = &l };
	cbl_msg *m = req(f, CBL_YCMD_EDIT, user), *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_locked, &d));
	error = cbl_request(f->c, m, &r, 5000);
	cbl_msg_free(r);
	return (error);
}

/* An rpc of nacmdemo, as user: its errno. */
static int
call(struct fixture *f, const char *user, const struct cbl_ynode *rpc)
{
	struct nacmdemo_echo_input in = { 0 };
	cbl_msg *m = req(f, CBL_YCMD_RPC, user), *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, io(rpc, CBL_YN_INPUT), &in));
	error = cbl_request(f->c, m, &r, 5000);
	cbl_msg_free(r);
	return (error);
}

/* An op of the family nd, as user: its errno. */
static int
op(struct fixture *f, const char *user, uint16_t cmd)
{
	cbl_msg *m, *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_msg_new(f->cctx, cbl_family_id(f->fam), cmd, 0,
	    &m));
	if (user != NULL)
		ATF_REQUIRE_EQ(0, cbl_msg_set_user(m, user));
	error = cbl_request(f->c, m, &r, 5000);
	cbl_msg_free(r);
	return (error);
}

static struct cbl_ynacm_counts
counts(struct fixture *f)
{
	struct cbl_ynacm_counts c;

	cbl_ynacm_counters(f->sctx, &c);
	return (c);
}

/* The admin's rule permits everything, the secret and reboot too. */
ATF_TC_WITHOUT_HEAD(admin);
ATF_TC_BODY(admin, tc)
{
	struct fixture f;
	bool pub, sec;
	size_t items;

	setup(&f);
	ATF_REQUIRE_EQ(0, get_data(&f, "alice", &pub, &sec, &items));
	ATF_CHECK(pub && sec && items == 1);
	ATF_CHECK_EQ(0, edit_locked(&f, "alice", 5));
	ATF_CHECK_EQ(0, call(&f, "alice", n_reboot));
	ATF_CHECK_EQ(0, call(&f, "alice", n_ping));
	ATF_CHECK_EQ(0, op(&f, "alice", 2));
	ATF_CHECK_EQ(0u, counts(&f).denied_operations);
	teardown(&f);
}

/*
 * The limited group: the secret left out of what it reads; writes
 * denied but its own item; ping denied by its rule, reboot by
 * nacm:default-deny-all, echo permitted by default; the family's
 * change denied, look not.
 */
ATF_TC_WITHOUT_HEAD(limited);
ATF_TC_BODY(limited, tc)
{
	static const struct nacmdemo_data_item two[] = {
		{ .name = "bob", .note = "b" }, { .name = "carol", .note = "c" } };
	static const struct nacmdemo_data_item carol2[] = {
		{ .name = "bob", .note = "b" }, { .name = "carol", .note = "x" } };
	static const struct nacmdemo_data_item one[] = {
		{ .name = "carol", .note = "c" } };
	struct fixture f;
	uint64_t at;
	bool pub, sec;
	size_t items;

	setup(&f);
	ATF_REQUIRE_EQ(0, get_data(&f, "bob", &pub, &sec, &items));
	ATF_CHECK(pub && !sec && items == 1);
	ATF_CHECK_EQ(EACCES, edit_data(&f, "bob", "changed", one, 1, &at));
	ATF_CHECK_EQ(child_sid(n_data, "public"), at);
	ATF_CHECK_EQ(EACCES, edit_locked(&f, "bob", 6));
	/* An item named after him: his to make; carol's not his. */
	ATF_CHECK_EQ(0, edit_data(&f, "bob", "hi", two, 2, NULL));
	ATF_CHECK_EQ(EACCES, edit_data(&f, "bob", "hi", carol2, 2, NULL));
	ATF_CHECK_EQ(EACCES, edit_data(&f, "dave", "hi", one, 1, NULL));
	ATF_CHECK_EQ(4u, counts(&f).denied_data_writes);
	ATF_CHECK_EQ(EACCES, call(&f, "bob", n_ping));
	ATF_CHECK_EQ(EACCES, call(&f, "bob", n_reboot));
	ATF_CHECK_EQ(0, call(&f, "bob", n_echo));
	ATF_CHECK_EQ(0, op(&f, "bob", 1));
	ATF_CHECK_EQ(EACCES, op(&f, "bob", 2));
	ATF_CHECK_EQ(3u, counts(&f).denied_operations);
	teardown(&f);
}

/* No group: the defaults alone. */
ATF_TC_WITHOUT_HEAD(nogroup);
ATF_TC_BODY(nogroup, tc)
{
	static const struct nacmdemo_data_item one[] = {
		{ .name = "carol", .note = "c" } };
	struct fixture f;
	bool pub, sec;
	size_t items;

	setup(&f);
	ATF_REQUIRE_EQ(0, get_data(&f, "carol", &pub, &sec, &items));
	ATF_CHECK(pub && !sec && items == 1);
	ATF_CHECK_EQ(EACCES, edit_data(&f, "carol", "x", one, 1, NULL));
	ATF_CHECK_EQ(0, call(&f, "carol", n_ping));
	ATF_CHECK_EQ(EACCES, call(&f, "carol", n_reboot));
	teardown(&f);
}

/* The recovery session: nothing held back; a peer that may not say whom
 * it asks for refused. */
ATF_TC_WITHOUT_HEAD(recovery);
ATF_TC_BODY(recovery, tc)
{
	struct fixture f;
	bool pub, sec;
	size_t items;

	setup(&f);
	ATF_REQUIRE_EQ(0, get_data(&f, NULL, &pub, &sec, &items));
	ATF_CHECK(pub && sec);
	ATF_CHECK_EQ(0, edit_locked(&f, NULL, 7));
	ATF_CHECK_EQ(0, call(&f, NULL, n_reboot));
	ATF_CHECK_EQ(0, op(&f, NULL, 2));
	ATF_CHECK_EQ(EACCES, get_data(&f, "mallory", &pub, &sec, &items));
	ATF_CHECK_EQ(EACCES, op(&f, "mallory", 1));
	teardown(&f);
}

/* The rules are ietf-netconf-acm's own default-deny-all: the admin
 * turns NACM off, which bob may not; then bob writes. */
ATF_TC_WITHOUT_HEAD(disable);
ATF_TC_BODY(disable, tc)
{
	static const struct nacmdemo_data_item one[] = {
		{ .name = "carol", .note = "c" } };
	struct ietf_netconf_acm_nacm off = { .has_enable_nacm = true,
	    .enable_nacm = false };
	struct ietf_netconf_acm d = { .nacm = &off };
	struct fixture f;
	cbl_msg *m, *r;

	setup(&f);
	m = req(&f, CBL_YCMD_EDIT, "bob");
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_nacm, &d));
	r = NULL;
	ATF_CHECK_EQ(EACCES, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	ATF_CHECK_EQ(EACCES, edit_data(&f, "bob", "x", one, 1, NULL));
	m = req(&f, CBL_YCMD_EDIT, "alice");
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_nacm, &d));
	r = NULL;
	ATF_CHECK_EQ(0, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	ATF_CHECK_EQ(0, edit_data(&f, "bob", "x", one, 1, NULL));
	ATF_CHECK_EQ(0, call(&f, "bob", n_reboot));
	teardown(&f);
}

/* A connection's user: each request it sends made for bob, but one that
 * says alice; a thread's user before the connection's. */
ATF_TC_WITHOUT_HEAD(conn_user);
ATF_TC_BODY(conn_user, tc)
{
	struct fixture f;

	setup(&f);
	ATF_REQUIRE_EQ(0, cbl_conn_set_user(f.c, "bob"));
	ATF_CHECK_EQ(EACCES, call(&f, NULL, n_reboot));
	ATF_CHECK_EQ(EACCES, op(&f, NULL, 2));
	ATF_CHECK_EQ(0, call(&f, "alice", n_reboot));
	ATF_REQUIRE_EQ(0, cbl_conn_set_user(f.c, NULL));
	ATF_CHECK_EQ(0, call(&f, NULL, n_reboot));
	/* The thread's, before the connection's. */
	ATF_REQUIRE_EQ(0, cbl_conn_set_user(f.c, "alice"));
	ATF_REQUIRE_EQ(0, cbl_thread_set_user("bob"));
	ATF_CHECK_EQ(EACCES, call(&f, NULL, n_reboot));
	ATF_REQUIRE_EQ(0, cbl_thread_set_user(NULL));
	ATF_CHECK_EQ(0, call(&f, NULL, n_reboot));
	teardown(&f);
}

/* The rules changed by a commit of the candidate (datastores on): read
 * again at once, as an EDIT of running has them. */
ATF_TC_WITHOUT_HEAD(commit);
ATF_TC_BODY(commit, tc)
{
	static const struct nacmdemo_data_item one[] = {
		{ .name = "carol", .note = "c" } };
	struct ietf_netconf_acm_nacm off = { .has_enable_nacm = true,
	    .enable_nacm = false };
	struct ietf_netconf_acm d = { .nacm = &off };
	struct ietf_netconf_commit_input in = { 0 };
	const struct cbl_ynode *n_commit = top("ietf-netconf", "commit");
	struct fixture f;
	cbl_msg *m, *r;

	setup(&f);
	ATF_REQUIRE_EQ(0, cbl_ydatastores(f.sctx, 0, NULL, NULL));
	ATF_CHECK_EQ(EACCES, edit_data(&f, "bob", "x", one, 1, NULL));
	m = req(&f, CBL_YCMD_EDIT, "alice");
	ATF_REQUIRE_EQ(0, cbl_msg_set_datastore(m, CBL_YDS_CANDIDATE));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_nacm, &d));
	r = NULL;
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	ATF_CHECK_EQ(EACCES, edit_data(&f, "bob", "x", one, 1, NULL));
	m = req(&f, CBL_YCMD_RPC, "alice");
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, io(n_commit, CBL_YN_INPUT),
	    &in));
	r = NULL;
	ATF_REQUIRE_EQ(0, cbl_request(f.c, m, &r, 5000));
	cbl_msg_free(r);
	ATF_CHECK_EQ(0, edit_data(&f, "bob", "x", one, 1, NULL));
	teardown(&f);
}

struct heard {
	uint64_t	 sids[8];
	int		 n;
};

static void
heard_cb(cbl_conn *conn, cbl_msg *m, void *arg)
{
	struct heard *h = arg;
	struct cbl_ynotif nt;
	cbl_yarena *a;

	(void)conn;
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	if (cbl_msg_ynotif(m, &nt, a) == 0 && h->n < 8)
		h->sids[h->n++] = nt.sid;
	cbl_yarena_free(a);
}

static void
pump(struct fixture *f, struct heard *h, int want)
{
	struct timespec t0, t1;
	struct pollfd pfd;
	int events, timeout;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (h->n < want) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ATF_REQUIRE(t1.tv_sec - t0.tv_sec < 5);
		cbl_conn_interest(f->c, &events, &timeout);
		pfd.fd = cbl_conn_fd(f->c);
		pfd.events = POLLIN | ((events & CBL_EV_WRITE) ? POLLOUT : 0);
		(void)poll(&pfd, 1, 10);
		(void)cbl_conn_process(f->c,
		    ((pfd.revents & POLLIN) ? CBL_EV_READ : 0) |
		    ((pfd.revents & POLLOUT) ? CBL_EV_WRITE : 0));
	}
}

/* Group "notify": bob is sent the event, not the alarm
 * nacm:default-deny-all marks; the denial counted. */
ATF_TC_WITHOUT_HEAD(notify);
ATF_TC_BODY(notify, tc)
{
	struct nacmdemo_alarm al = { .what = "hot" };
	struct nacmdemo_event ev = { .what = "up" };
	struct heard h = { 0 };
	struct fixture f;
	cbl_sub *sub;

	setup(&f);
	dflt_user = "bob";
	ATF_REQUIRE_EQ(0, cbl_subscribe(f.c, "cblink.yang", "notify",
	    heard_cb, &h, &sub));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_alarm, &al));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_event, &ev));
	pump(&f, &h, 1);
	ATF_CHECK_EQ(1, h.n);
	ATF_CHECK_EQ(n_event->sid, h.sids[0]);
	ATF_CHECK_EQ(1u, counts(&f).denied_notifications);
	ATF_REQUIRE_EQ(0, cbl_unsubscribe(sub));
	teardown(&f);
}

/*
 * Rules of a case's own in the limited group's place: n rules, each
 * {name, path, ops (access-operations' bits), permit}; the exec and
 * read defaults as given.
 */
struct crule {
	const char	*name;
	const char	*path;
	uint8_t		 ops;
	bool		 permit;
	bool		 anymod;	/* module-name "*", not nacmdemo */
};

static void
custom(const struct crule *cr, size_t n, bool exec_permit)
{
	static const char *const admins[] = { "alice" };
	static const char *const limited[] = { "bob", "dave" };
	static const struct ietf_netconf_acm_nacm_groups_group g[] = {
		{ .name = "admin", .user_name = { 1, admins } },
		{ .name = "limited", .user_name = { 2, limited } },
	};
	static const struct ietf_netconf_acm_nacm_groups gs = {
		.group = { 2, g } };
	static const struct ietf_netconf_acm_nacm_rule_list_group ga[] = {
		{ .which = 1, .v.m1 = "admin" } };
	static const struct ietf_netconf_acm_nacm_rule_list_group gl[] = {
		{ .which = 1, .v.m1 = "limited" } };
	static uint8_t bits[8];
	struct ietf_netconf_acm_nacm_rule_list_rule ra[] = {
		{ .name = "permit-all", .has_module_name = true,
		    .module_name = { .which = 0, .v.m0 = "*" },
		    .has_access_operations = true,
		    .access_operations = { .which = 0, .v.m0 = "*" },
		    .has_action = true,
		    .action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT },
	};
	struct ietf_netconf_acm_nacm_rule_list_rule rl[8];
	struct ietf_netconf_acm_nacm_rule_list l[] = {
		{ .name = "admin-acl", .group = { 1, ga },
		    .rule = { nitems(ra), ra } },
		{ .name = "limited-acl", .group = { 1, gl },
		    .rule = { n, rl } },
	};
	struct ietf_netconf_acm_nacm nacm = {
		.has_enable_nacm = true, .enable_nacm = true,
		.has_exec_default = true, .exec_default = exec_permit ?
		IETF_NETCONF_ACM_NACM_EXEC_DEFAULT_PERMIT :
		IETF_NETCONF_ACM_NACM_EXEC_DEFAULT_DENY,
		.groups = &gs, .rule_list = { nitems(l), l },
	};
	struct ietf_netconf_acm d = { .nacm = &nacm };

	ATF_REQUIRE(n <= nitems(rl));
	memset(rl, 0, sizeof(rl));
	for (size_t i = 0; i < n; i++) {
		bits[i] = cr[i].ops;
		rl[i] = (struct ietf_netconf_acm_nacm_rule_list_rule){
		    .name = cr[i].name, .has_module_name = true,
		    .module_name = cr[i].anymod ?
		    (__typeof__(rl[i].module_name)){ .which = 0, .v.m0 = "*" } :
		    (__typeof__(rl[i].module_name)){ .which = 1,
		    .v.m1 = "nacmdemo" },
		    .rule_type =
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_RULE_TYPE_DATA_NODE,
		    .path = cr[i].path, .has_access_operations = true,
		    .access_operations = { .which = 1, .v.m1 = { &bits[i],
		    1 } },
		    .has_action = true,
		    .action = cr[i].permit ?
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_PERMIT :
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_DENY };
	}
	ATF_REQUIRE_EQ(0, kset(2, &d));
}

#define	B_CREATE	(1u << 0)
#define	B_READ		(1u << 1)
#define	B_UPDATE	(1u << 2)
#define	B_DELETE	(1u << 3)
#define	B_EXEC		(1u << 4)

/* item key's reset, as user: its errno. */
static int
reset(struct fixture *f, const char *user, const char *key)
{
	struct nacmdemo_data_item_reset_input in = { 0 };
	struct cbl_ybuf t = { NULL, 0, 0 };
	const void *vals[] = { &key };
	cbl_msg *m = req(f, CBL_YCMD_RPC, user), *r = NULL;
	int error;

	ATF_REQUIRE_EQ(0, cbl_yiid_write(n_item, vals, 1, &t));
	ATF_REQUIRE_EQ(0, cbl_msg_put_ynode(m, io(n_reset, CBL_YN_INPUT),
	    &in));
	ATF_REQUIRE_EQ(0, cbl_msg_put_yaction(m, t.p, t.len));
	error = cbl_request(f->c, m, &r, 5000);
	cbl_msg_free(r);
	cbl_ybuf_free(&t);
	return (error);
}

/*
 * An action is run on an instance: a path rule's key predicates are held
 * to its target's keys.  A deny of one item's reset, the default
 * permitting the rest; then the default denying, a permit of the item
 * named after the user ($USER).
 */
ATF_TC_WITHOUT_HEAD(action_keys);
ATF_TC_BODY(action_keys, tc)
{
	static const struct crule deny_core[] = {
		{ "deny-core-reset", "/nacmdemo:data/nacmdemo:item"
		    "[nacmdemo:name='core']/nacmdemo:reset",
		    B_EXEC, false, false },
	};
	static const struct crule own[] = {
		{ "own-reset", "/nacmdemo:data/nacmdemo:item"
		    "[nacmdemo:name=$USER]/nacmdemo:reset",
		    B_EXEC, true, false },
	};
	struct fixture f;

	setup(&f);
	custom(deny_core, nitems(deny_core), true);
	ATF_CHECK_EQ(EACCES, reset(&f, "bob", "core"));
	ATF_CHECK_EQ(0, reset(&f, "bob", "edge"));
	ATF_CHECK_EQ(0, reset(&f, "alice", "core"));
	custom(own, nitems(own), false);
	cbl_ynacm_changed(f.sctx);
	ATF_CHECK_EQ(0, reset(&f, "bob", "bob"));
	ATF_CHECK_EQ(EACCES, reset(&f, "bob", "dave"));
	ATF_CHECK_EQ(0, reset(&f, "dave", "dave"));
	ATF_CHECK_EQ(EACCES, call(&f, "bob", n_echo));
	teardown(&f);
}

/*
 * A notification of a list entry is sent without the entry's keys: a
 * deny with key predicates is not skipped for that, it holds; the
 * event, which no rule names, still goes.
 */
ATF_TC_WITHOUT_HEAD(notify_keys);
ATF_TC_BODY(notify_keys, tc)
{
	static const struct crule deny_core[] = {
		{ "deny-core-changed", "/nacmdemo:data/nacmdemo:item"
		    "[nacmdemo:name='core']/nacmdemo:changed",
		    B_READ, false, false },
	};
	struct nacmdemo_data_item_changed ch = { .what = "note" };
	struct nacmdemo_event ev = { .what = "up" };
	struct heard h = { 0 };
	struct fixture f;
	cbl_sub *sub;

	setup(&f);
	custom(deny_core, nitems(deny_core), true);
	dflt_user = "bob";
	ATF_REQUIRE_EQ(0, cbl_subscribe(f.c, "cblink.yang", "notify",
	    heard_cb, &h, &sub));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_changed, &ch));
	ATF_REQUIRE_EQ(0, cbl_ynotify(f.sctx, n_event, &ev));
	pump(&f, &h, 1);
	ATF_CHECK_EQ(1, h.n);
	ATF_CHECK_EQ(n_event->sid, h.sids[0]);
	ATF_CHECK_EQ(1u, counts(&f).denied_notifications);
	ATF_REQUIRE_EQ(0, cbl_unsubscribe(sub));
	teardown(&f);
}

/*
 * A path rule that does not compile (a prefix, not a module's name): a
 * deny one denies, to its rule-list's groups and for its operations,
 * all of its module (its module-name, nacmdemo), the other groups as
 * they were; with module-name "*" and a path whose first step is no
 * module, every module; cbl_ynacm_status() telling why.  A permit one
 * never matches, told too.  An EDIT that would write either refused.
 */
ATF_TC_WITHOUT_HEAD(bad_path);
ATF_TC_BODY(bad_path, tc)
{
	static const struct crule bad_deny[] = {
		{ "deny-if", "/if:interfaces", B_READ | B_UPDATE, false, false },
		{ "own-item", "/nacmdemo:data/nacmdemo:item"
		    "[nacmdemo:name=$USER]", B_CREATE | B_UPDATE | B_DELETE,
		    true, false },
	};
	static const struct crule bad_any[] = {
		{ "deny-any", "/if:interfaces", B_READ | B_UPDATE | B_EXEC,
		    false, true },
	};
	static const struct crule bad_permit[] = {
		{ "permit-typo", "/nacmdemo:dta", B_READ, true, false },
	};
	struct ietf_netconf_acm_nacm_rule_list_rule rl[] = {
		{ .name = "deny-typo", .has_module_name = true,
		    .module_name = { .which = 0, .v.m0 = "*" },
		    .rule_type =
		    IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_RULE_TYPE_DATA_NODE,
		    .path = "/nacmdemo:data/nacmdemo:scret",
		    .has_access_operations = true,
		    .access_operations = { .which = 0, .v.m0 = "*" },
		    .has_action = true,
		    .action = IETF_NETCONF_ACM_NACM_RULE_LIST_RULE_ACTION_DENY },
	};
	struct ietf_netconf_acm_nacm_rule_list l[] = {
		{ .name = "typo-acl", .group = { 0, NULL },
		    .rule = { nitems(rl), rl } },
	};
	struct ietf_netconf_acm_nacm nacm = { .has_enable_nacm = true,
	    .enable_nacm = true, .rule_list = { nitems(l), l } };
	struct ietf_netconf_acm d = { .nacm = &nacm };
	struct fixture f;
	char why[256];
	cbl_msg *m, *r;
	bool pub, sec;
	size_t items;

	setup(&f);
	ATF_CHECK_EQ(0, cbl_ynacm_status(f.sctx, why, sizeof(why)));
	custom(bad_deny, nitems(bad_deny), true);
	cbl_ynacm_changed(f.sctx);
	/* The limited group: nacmdemo not read, not written; exec, which
	 * the rule does not name, as it was. */
	ATF_REQUIRE_EQ(0, get_data(&f, "bob", &pub, &sec, &items));
	ATF_CHECK(!pub && !sec && items == 0);
	ATF_CHECK_EQ(EACCES, edit_locked(&f, "bob", 9));
	ATF_CHECK_EQ(0, call(&f, "bob", n_echo));
	/* The other groups, and no group, as they were. */
	ATF_REQUIRE_EQ(0, get_data(&f, "alice", &pub, &sec, &items));
	ATF_CHECK(pub && sec && items == 1);
	ATF_CHECK_EQ(0, edit_locked(&f, "alice", 9));
	ATF_REQUIRE_EQ(0, get_data(&f, "carol", &pub, &sec, &items));
	ATF_CHECK(pub && !sec);
	ATF_CHECK_EQ(0, call(&f, NULL, n_echo));
	ATF_CHECK_EQ(EACCES, cbl_ynacm_status(f.sctx, why, sizeof(why)));
	ATF_CHECK_MSG(strstr(why, "deny-if") != NULL &&
	    strstr(why, "/if:interfaces") != NULL, "%s", why);
	/* Of no module it can tell: every module, still its group's. */
	custom(bad_any, nitems(bad_any), true);
	cbl_ynacm_changed(f.sctx);
	ATF_REQUIRE_EQ(0, get_data(&f, "bob", &pub, &sec, &items));
	ATF_CHECK(!pub && !sec && items == 0);
	ATF_CHECK_EQ(EACCES, call(&f, "bob", n_echo));
	ATF_CHECK_EQ(0, call(&f, "carol", n_echo));
	ATF_CHECK_EQ(EACCES, cbl_ynacm_status(f.sctx, why, sizeof(why)));
	custom(bad_permit, nitems(bad_permit), true);
	cbl_ynacm_changed(f.sctx);
	ATF_REQUIRE_EQ(0, get_data(&f, "bob", &pub, &sec, &items));
	ATF_CHECK(pub && !sec && items == 1);
	ATF_CHECK_EQ(EINVAL, cbl_ynacm_status(f.sctx, why, sizeof(why)));
	ATF_CHECK_MSG(strstr(why, "permit-typo") != NULL &&
	    strstr(why, "never matches") != NULL, "%s", why);
	/* Written by the admin: refused, the rules as they were. */
	rules(true);
	cbl_ynacm_changed(f.sctx);
	m = req(&f, CBL_YCMD_EDIT, "alice");
	ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_nacm, &d));
	r = NULL;
	ATF_CHECK_EQ(EINVAL, cbl_request(f.c, m, &r, 5000));
	ATF_CHECK_MSG(r != NULL && strstr(cbl_msg_err_str(r), "deny-typo") !=
	    NULL, "%s", r != NULL ? cbl_msg_err_str(r) : "no reply");
	cbl_msg_free(r);
	ATF_CHECK_EQ(0, cbl_ynacm_status(f.sctx, why, sizeof(why)));
	ATF_REQUIRE_EQ(0, get_data(&f, "alice", &pub, &sec, &items));
	ATF_CHECK(pub && sec);
	teardown(&f);
}

/*
 * A delete is checked on every node it takes away (RFC 8341 section
 * 3.2.5): sys may be deleted, users in it may not, so sys with users
 * is not; sys without them is.
 */
ATF_TC_WITHOUT_HEAD(delete_below);
ATF_TC_BODY(delete_below, tc)
{
	static const struct crule rl[] = {
		{ "keep-users", "/nacmdemo:data/nacmdemo:sys/nacmdemo:users",
		    B_DELETE, false, false },
		{ "sys", "/nacmdemo:data/nacmdemo:sys", B_CREATE | B_UPDATE |
		    B_DELETE, true, false },
	};
	static const struct nacmdemo_data_item items[] = {
		{ .name = "carol", .note = "c" } };
	struct nacmdemo_data_sys_users u = { .has_n = true, .n = 1 };
	struct nacmdemo_data_sys sy = { .users = &u }, empty = { 0 };
	struct nacmdemo_data dd = { .public = "hi", .secret = "s3",
	    .item = { 1, items }, .sys = &sy };
	struct nacmdemo d = { .data = &dd };
	struct fixture f;

	setup(&f);
	custom(rl, nitems(rl), true);
	ATF_REQUIRE_EQ(0, kset(0, &d));
	ATF_CHECK_EQ(EACCES, edit_data(&f, "bob", "hi", items, 1, NULL));
	ATF_CHECK_EQ(1u, counts(&f).denied_data_writes);
	dd.sys = &empty;
	ATF_REQUIRE_EQ(0, kset(0, &d));
	ATF_CHECK_EQ(0, edit_data(&f, "bob", "hi", items, 1, NULL));
	teardown(&f);
}

/*
 * What running had wrong before an edit, in a node the edit leaves as
 * it was, is a warning: named to who may read the node (the admin),
 * not to who may not (bob: hidden-ref is nacm:default-deny-all).
 */
ATF_TC_WITHOUT_HEAD(warning_named);
ATF_TC_BODY(warning_named, tc)
{
	static const struct nacmdemo_data_item two[] = {
		{ .name = "bob", .note = "b" }, { .name = "carol", .note = "c" } };
	struct nacmdemo_locked l = { .hidden_ref = "gone" };
	struct nacmdemo dl = { .locked = &l };
	struct nacmdemo_data dd = { .public = "hi", .secret = "s3",
	    .item = { 2, two } };
	struct nacmdemo d = { .data = &dd };
	const struct cbl_ywarning *w;
	const char *who[] = { "bob", "alice" };
	struct fixture f;
	cbl_yarena *a;
	cbl_msg *m, *r;
	size_t nw;

	setup(&f);
	ATF_REQUIRE_EQ(0, kset(1, &dl));
	for (int i = 0; i < 2; i++) {
		m = req(&f, CBL_YCMD_EDIT, who[i]);
		dd.item.n = i == 0 ? 2 : 1;
		dd.item.v = i == 0 ? two : two + 1;
		ATF_REQUIRE_EQ(0, cbl_msg_put_ymember(m, n_data, &d));
		r = NULL;
		ATF_REQUIRE_EQ_MSG(0, cbl_request(f.c, m, &r, 5000), "%s: %s",
		    who[i], r != NULL ? cbl_msg_err_str(r) : "");
		ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
		nw = 0;
		ATF_CHECK(cbl_msg_ywarnings(r, a, &w, &nw) == 0 && nw == 1);
		if (nw == 1 && i == 0)
			ATF_CHECK_MSG(w[0].sid == 0 &&
			    strstr(w[0].text, "hidden-ref") == NULL, "%s",
			    w[0].text);
		else if (nw == 1)
			ATF_CHECK_MSG(w[0].sid == child_sid(n_locked,
			    "hidden-ref") && strstr(w[0].text, "hidden-ref") !=
			    NULL, "%s", w[0].text);
		cbl_yarena_free(a);
		cbl_msg_free(r);
	}
	teardown(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, admin);
	ATF_TP_ADD_TC(tp, limited);
	ATF_TP_ADD_TC(tp, nogroup);
	ATF_TP_ADD_TC(tp, recovery);
	ATF_TP_ADD_TC(tp, disable);
	ATF_TP_ADD_TC(tp, notify);
	ATF_TP_ADD_TC(tp, conn_user);
	ATF_TP_ADD_TC(tp, commit);
	ATF_TP_ADD_TC(tp, action_keys);
	ATF_TP_ADD_TC(tp, notify_keys);
	ATF_TP_ADD_TC(tp, bad_path);
	ATF_TP_ADD_TC(tp, delete_below);
	ATF_TP_ADD_TC(tp, warning_named);
	return (atf_no_error());
}
