/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: the paths a peer names nodes by, over the module shapes
 * (yshapes.h: a keyed list, leaf-lists, instance-identifier leaves):
 *
 * - an instance-identifier as YANG-CBOR has it (RFC 9254 section
 *   6.13.1: a SID, or [SID, keys...]), cbl_yiid_read(); what reads is
 *   written again (cbl_yiid_write()), and that reads to the same node;
 * - as RFC 7951's JSON has it, XPath ("/shapes:shapes/item[id='1']"),
 *   made YANG-CBOR by cbl_yxlate_iid() over the tables' own numbering;
 *   what it makes cbl_yiid_read() takes, and writes again to the same
 *   bytes;
 * - a schema-node path (RFC 9595's identifier), cbl_ysids_data(): the
 *   item found has a path of its own that finds it again;
 * - a NACM data-node rule path (RFC 8341 section 3.4.5, as an edit of
 *   the rules brings one), compiled and matched against every node of a
 *   tree and every node of the schema;
 * - a value read from its canonical string (cbl_yvalue_parse(), a key's
 *   or an rpc's input), as the leaf or leaf-list the first byte picks.
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_data.h"
#include "cbl_schema.h"
#include "cbl_yxlate.h"
#include "yshapes.h"

int	LLVMFuzzerInitialize(int *argc, char ***argv);
int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define	ARENA_LIMIT	(1 << 20)
#define	MAXLEAVES	64

static struct cbl_ysids *sids;
static cbl_dtree *tree;
static const struct cbl_ynode *leaves[MAXLEAVES];
static size_t nleaves;

/* A tree to match NACM paths against: two list entries, a leaf-list. */
static void
make_tree(void)
{
	static const char *const names[] = { "a", "b'c" };
	static const struct shapes_shapes_item items[] = {
	    { .id = 1, .has_peer = true, .peer = 2 },
	    { .id = 2 } };
	const struct cbl_ynode *top = NULL;
	struct shapes_shapes sh = { 0 };
	cbl_dnode *n;

	for (uint32_t i = 0; i < yshapes_schema.nmod; i++)
		for (uint32_t j = 0; j < yshapes_schema.mod[i]->ntop; j++)
			if (strcmp(yshapes_schema.mod[i]->top[j]->name,
			    "shapes") == 0)
				top = yshapes_schema.mod[i]->top[j];
	sh.default_ = "x";
	sh.names.n = 2;
	sh.names.v = names;
	sh.item.n = 2;
	sh.item.v = items;
	if (top == NULL || (tree = cbl_dtree_new(&yshapes_schema)) == NULL ||
	    cbl_dnode_from_struct(cbl_dtree_root(tree), top, &sh, &n) != 0)
		abort();
}

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{
	char why[256];

	if ((sids = cbl_ysids_new(&yshapes_schema)) == NULL ||
	    cbl_ysids_tables(sids) != 0 ||
	    cbl_ysids_done(sids, why, sizeof(why)) != 0)
		abort();
	for (uint32_t i = 0; i < yshapes_schema.nnode; i++) {
		const struct cbl_ynode *n = yshapes_schema.node[i];

		if ((n->kind == CBL_YN_LEAF || n->kind == CBL_YN_LEAFLIST) &&
		    nleaves < MAXLEAVES)
			leaves[nleaves++] = n;
	}
	if (nleaves == 0)
		abort();
	make_tree();
	return (0);
}

/* v's instance-identifier read, written, and read again to the same. */
static void
iid_cbor(const void *p, size_t len, bool canonical)
{
	struct cbl_bytes v = { p, len }, w;
	const struct cbl_ynode *n, *n2;
	struct cbl_ybuf b = { 0 };
	const void **vals, **vals2;
	size_t nvals, nvals2;
	cbl_yarena *a;

	if ((a = cbl_yarena_new()) == NULL)
		abort();
	cbl_yarena_set_limit(a, ARENA_LIMIT);
	if (cbl_yiid_read(&yshapes_schema, &v, &n, &vals, &nvals, a) != 0) {
		/* What the translator makes, the reader takes. */
		if (canonical)
			abort();
		goto out;
	}
	if (cbl_yiid_write(n, vals, nvals, &b) != 0)
		abort();
	if (canonical && (b.len != len || memcmp(b.p, p, len) != 0))
		abort();
	w = (struct cbl_bytes){ b.p, b.len };
	if (cbl_yiid_read(&yshapes_schema, &w, &n2, &vals2, &nvals2, a) != 0 ||
	    n2 != n || nvals2 != nvals)
		abort();
out:
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
}

static void
iid_xpath(const char *s)
{
	struct cbl_ybuf b = { 0 };
	char why[256];

	if (cbl_yxlate_iid(sids, s, &b, why, sizeof(why)) == 0)
		iid_cbor(b.p, b.len, true);
	cbl_ybuf_free(&b);
}

static void
schema_path(const char *s)
{
	const struct cbl_ysid_item *it;
	char path[512];

	if ((it = cbl_ysids_data(sids, s)) == NULL || it->what == NULL)
		return;
	if (cbl_ysids_node_path(it->what, path, sizeof(path)) &&
	    cbl_ysids_data(sids, path) != it)
		abort();
}

static void
match_all(const cbl_dnacm_path *p, const cbl_dnode *n, int depth)
{

	if (depth > 16)
		return;
	for (const cbl_dnode *c = cbl_dnode_first(n); c != NULL;
	    c = cbl_dnode_next(c)) {
		(void)cbl_dnacm_path_match(p, c, "fuzz");
		(void)cbl_dnacm_path_match(p, c, NULL);
		match_all(p, c, depth + 1);
	}
}

static void
nacm_path(const char *s)
{
	cbl_dnacm_path *p;
	char why[256];

	if ((p = cbl_dnacm_path_new(&yshapes_schema, s, why,
	    sizeof(why))) == NULL)
		return;
	match_all(p, cbl_dtree_root(tree), 0);
	for (uint32_t i = 0; i < yshapes_schema.nnode; i++)
		(void)cbl_dnacm_path_match_schema(p, yshapes_schema.node[i]);
	cbl_dnacm_path_free(p);
}

static void
value(const struct cbl_ynode *n, const char *s)
{
	alignas(max_align_t) char out[256];
	cbl_yarena *a;

	if (n->type == NULL || n->type->csize > sizeof(out))
		return;
	if ((a = cbl_yarena_new()) == NULL)
		abort();
	cbl_yarena_set_limit(a, ARENA_LIMIT);
	(void)cbl_yvalue_parse(n, n->type, s, out, a);
	cbl_yarena_free(a);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *s;

	iid_cbor(data, size, false);
	if ((s = malloc(size + 1)) == NULL)
		return (0);
	memcpy(s, data, size);
	s[size] = '\0';
	iid_xpath(s);
	schema_path(s);
	nacm_path(s);
	if (size > 0)
		value(leaves[data[0] % nleaves], s + 1);
	free(s);
	return (0);
}
