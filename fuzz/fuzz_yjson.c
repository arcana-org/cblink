/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libFuzzer: JSON as a person or a RESTCONF-like client writes it, read
 * by the library: the JSON reader (cbl_json.c) alone; RFC 7951's JSON of
 * the module shapes (yshapes.h: every kind of node and type) made
 * YANG-CBOR by the translator (cbl_yxlate.c) over the tables' own
 * numbering, as an object of top-level nodes and as one node's value
 * (the first byte picks the node); and a .sid file in RFC 9595's JSON.
 * What translates is translated back to JSON, which translates to the
 * same CBOR; and it decodes by the local codec as the node's struct.
 */

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cbl_json.h"
#include "cbl_schema.h"
#include "cbl_yxlate.h"
#include "yshapes.h"

int	LLVMFuzzerInitialize(int *argc, char ***argv);
int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define	ARENA_LIMIT	(1 << 20)
#define	MAXTOPS		32

static struct cbl_ysids *sids;
static uint64_t tops[MAXTOPS];
static size_t ntops;
static alignas(max_align_t) char tree[4096];

int
LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{
	char why[256];

	if ((sids = cbl_ysids_new(&yshapes_schema)) == NULL ||
	    cbl_ysids_tables(sids) != 0 ||
	    cbl_ysids_done(sids, why, sizeof(why)) != 0)
		abort();
	ntops = cbl_ysids_tops(sids, tops, MAXTOPS);
	if (ntops == 0 || ntops > MAXTOPS)
		abort();
	return (0);
}

/* The JSON reader alone; what it reads, a tree of what it says. */
static void
reader(const uint8_t *data, size_t size)
{
	const struct cbl_jv *v;
	cbl_yarena *a;
	char why[128];

	if ((a = cbl_yarena_new()) == NULL)
		abort();
	cbl_yarena_set_limit(a, ARENA_LIMIT);
	if (cbl_json_parse(a, (const char *)data, size, &v, why,
	    sizeof(why)) == 0) {
		if (v == NULL)
			abort();
		(void)cbl_json_get(v, "shapes:shapes");
		(void)cbl_json_str(v);
	}
	cbl_yarena_free(a);
}

/* An object of top-level nodes: into CBOR, back to JSON, into the same
 * CBOR again. */
static void
object(const uint8_t *data, size_t size)
{
	struct cbl_ybuf c1 = { 0 }, j = { 0 }, c2 = { 0 };
	const char *tag;
	char why[256];

	if (cbl_yxlate_cbor(sids, (const char *)data, size, &c1, &tag, why,
	    sizeof(why)) == 0) {
		if (cbl_yxlate_json(sids, c1.p, c1.len, &j, why,
		    sizeof(why)) != 0)
			abort();
		if (cbl_yxlate_cbor(sids, (const char *)j.p, j.len, &c2, &tag,
		    why, sizeof(why)) != 0 || c1.len != c2.len ||
		    memcmp(c1.p, c2.p, c1.len) != 0)
			abort();
	}
	cbl_ybuf_free(&c1);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&c2);
}

/* One node's value: into CBOR, which its struct decodes; back to JSON
 * and into the same CBOR. */
static void
member(const struct cbl_ysid_item *it, const uint8_t *data, size_t size)
{
	struct cbl_ybuf c1 = { 0 }, j = { 0 }, c2 = { 0 };
	const struct cbl_ynode *n = it->what;
	const char *tag;
	bool first = true;
	char why[256];
	cbl_yarena *a;

	if (cbl_yxlate_cbor_member(sids, it, (const char *)data, size, &c1,
	    &tag, why, sizeof(why)) != 0)
		goto out;
	if (n != NULL && n->size > 0 && n->size <= sizeof(tree)) {
		if ((a = cbl_yarena_new()) == NULL)
			abort();
		cbl_yarena_set_limit(a, ARENA_LIMIT);
		(void)cbl_ydecode(n, c1.p, c1.len, tree, a, 0, NULL, 0);
		cbl_yarena_free(a);
	}
	if (cbl_yxlate_json_member(sids, it, c1.p, c1.len, &first, &j, why,
	    sizeof(why)) != 0)
		abort();
	/* "module:name": value; the value alone after the first colon
	 * outside the name's quotes. */
	{
		const char *p = memchr(j.p, ':', j.len);

		if (p == NULL || (p = memchr(p + 1, '"', j.len -
		    (size_t)(p + 1 - (const char *)j.p))) == NULL ||
		    (p = memchr(p, ':', j.len -
		    (size_t)(p - (const char *)j.p))) == NULL)
			abort();
		p++;
		if (cbl_yxlate_cbor_member(sids, it, p, j.len -
		    (size_t)(p - (const char *)j.p), &c2, &tag, why,
		    sizeof(why)) != 0 || c1.len != c2.len ||
		    memcmp(c1.p, c2.p, c1.len) != 0)
			abort();
	}
out:
	cbl_ybuf_free(&c1);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&c2);
}

/* A .sid file, added to a view of its own. */
static void
sidfile(const uint8_t *data, size_t size)
{
	struct cbl_ysids *s;
	uint64_t t[MAXTOPS];
	char why[256];

	if ((s = cbl_ysids_new(&yshapes_schema)) == NULL)
		abort();
	if (cbl_ysids_file_json(s, (const char *)data, size, why,
	    sizeof(why)) == 0 && cbl_ysids_done(s, why, sizeof(why)) == 0) {
		size_t nt = cbl_ysids_tops(s, t, MAXTOPS);

		for (size_t i = 0; i < nt && i < MAXTOPS; i++)
			if (cbl_ysids_sid(s, t[i]) == NULL)
				abort();
	}
	cbl_ysids_free(s);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct cbl_ysid_item *it;

	reader(data, size);
	object(data, size);
	sidfile(data, size);
	if (size > 0 &&
	    (it = cbl_ysids_sid(sids, tops[data[0] % ntops])) != NULL)
		member(it, data + 1, size - 1);
	return (0);
}
