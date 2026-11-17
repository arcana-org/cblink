/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The translator between RFC 7951's JSON and YANG-CBOR by a peer's SIDs
 * (cbl_yxlate.c, cbl_ysid.c) over the example modules in yang/yxlate:
 * RFC 7951's examples each way, checked against cblink's own codec
 * (what one writes the other reads, and its JSON is the same); RFC
 * 7952's annotations in the shape its section 5.2 has; a peer that
 * numbers the items otherwise, and one that has a node the local tables
 * do not; JSON that is not, refused.  The .sid files are read and
 * renumbered with base's libucl, and compared through it.
 */

#include <atf-c.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#include "cblink.h"
#include "cbl_schema.h"
#include "cbl_data.h"
#include "cbl_yxlate.h"

#include "yxtest.h"

static const char *const files[] = {
	"example-foomod@2026-11-05.sid",
	"example-barmod@2026-11-05.sid",
	"example-last-modified@2026-11-05.sid",
};

static ucl_object_t *
json(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE_MSG(ucl_parser_add_string(p, s, 0), "%s: %s", s,
	    ucl_parser_get_error(p));
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

static ucl_object_t *
json_file(const atf_tc_t *tc, const char *name)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			 path[512];

	snprintf(path, sizeof(path), "%s/yxlate/%s",
	    atf_tc_get_config_var(tc, "srcdir"), name);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE_MSG(ucl_parser_add_file(p, path), "%s", path);
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* Each item's SID moved by shift; one more item, extra, if given. */
static void
renumber(ucl_object_t *file, uint64_t shift, const char *extra,
    uint64_t extra_sid)
{
	ucl_object_t		*f, *items, *e;
	ucl_object_iter_t	 it = NULL;
	char			 buf[32];

	f = (ucl_object_t *)(uintptr_t)ucl_object_lookup(file,
	    "ietf-sid-file:sid-file");
	items = (ucl_object_t *)(uintptr_t)ucl_object_lookup(f, "item");
	while ((e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(items, &it,
	    true)) != NULL) {
		uint64_t sid = strtoull(ucl_object_tostring(ucl_object_lookup(e,
		    "sid")), NULL, 10) + shift;

		snprintf(buf, sizeof(buf), "%" PRIu64, sid);
		ucl_object_replace_key(e, ucl_object_fromstring(buf), "sid", 0,
		    false);
	}
	if (extra != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring("data"),
		    "namespace", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(extra),
		    "identifier", 0, false);
		snprintf(buf, sizeof(buf), "%" PRIu64, extra_sid);
		ucl_object_insert_key(e, ucl_object_fromstring(buf), "sid", 0,
		    false);
		ucl_array_append(items, e);
	}
}

/* The example modules' items, as the files have them (shift 0), or a
 * peer's numbering of them. */
static struct cbl_ysids *
view(const atf_tc_t *tc, uint64_t shift, const char *extra,
    uint64_t extra_sid)
{
	struct cbl_ysids	*s;
	ucl_object_t		*f;
	unsigned char		*t;
	char			 why[256];

	ATF_REQUIRE((s = cbl_ysids_new(&yxtest_schema)) != NULL);
	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		f = json_file(tc, files[i]);
		if (shift != 0 || (i == 0 && extra != NULL))
			renumber(f, shift, i == 0 ? extra : NULL, extra_sid);
		ATF_REQUIRE((t = ucl_object_emit(f, UCL_EMIT_JSON)) != NULL);
		ATF_REQUIRE_MSG(cbl_ysids_file_json(s, (const char *)t,
		    strlen((const char *)t), why, sizeof(why)) == 0, "%s", why);
		free(t);
		ucl_object_unref(f);
	}
	ATF_REQUIRE_MSG(cbl_ysids_done(s, why, sizeof(why)) == 0, "%s", why);
	return (s);
}

/* JSON text of what b holds. */
static char *
text(const struct cbl_ybuf *b)
{

	return (strndup(b->p != NULL ? (const char *)b->p : "", b->len));
}

/* doc into YANG-CBOR and back: the same; cblink reads the CBOR, and its
 * JSON of it is doc too, but where its JSON differs (CBL_JSON: an
 * instance-identifier's null) or its tables number otherwise. */
#define	CBL_ALL		0
#define	CBL_JSON	1
#define	NO_CBLINK	2

static void
both_ways(const struct cbl_ysids *s, const char *doc, int cbl)
{
	struct cbl_ybuf	 c = { NULL, 0, 0 }, j = { NULL, 0, 0 },
			 k = { NULL, 0, 0 };
	ucl_object_t	*want, *got;
	cbl_dtree	*t;
	const char	*tag = NULL;
	char		 why[256], *out;

	want = json(doc);
	ATF_REQUIRE_MSG(cbl_yxlate_cbor(s, doc, strlen(doc), &c, &tag, why,
	    sizeof(why)) == 0, "%s: %s %s", doc, tag, why);
	ATF_REQUIRE_MSG(cbl_yxlate_json(s, c.p, c.len, &j, why,
	    sizeof(why)) == 0, "%s: back: %s", doc, why);
	out = text(&j);
	got = json(out);
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s\n  came back "
	    "as %s", doc, out);
	ucl_object_unref(got);
	free(out);
	/* cblink's codec: it decodes what this wrote, strictly. */
	if (cbl == NO_CBLINK)
		goto done;
	ATF_REQUIRE((t = cbl_dtree_new(&yxtest_schema)) != NULL);
	ATF_CHECK_MSG(cbl_dtree_decode(t, c.p, c.len, CBL_YD_STRICT, why,
	    sizeof(why)) == 0, "%s: cblink: %s", doc, why);
	if (cbl == CBL_ALL) {
		ATF_REQUIRE(cbl_dtree_json(t, &k) == 0);
		out = text(&k);
		got = json(out);
		ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s\n  is "
		    "cblink's %s", doc, out);
		ucl_object_unref(got);
		free(out);
	}
	cbl_dtree_free(t);
done:
	ucl_object_unref(want);
	cbl_ybuf_free(&c);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&k);
}

/* doc refused with that error-tag. */
static void
refused(const struct cbl_ysids *s, const char *doc, const char *want)
{
	struct cbl_ybuf	 c = { NULL, 0, 0 };
	const char	*tag = NULL;
	char		 why[256];

	why[0] = '\0';
	ATF_CHECK_MSG(cbl_yxlate_cbor(s, doc, strlen(doc), &c, &tag, why,
	    sizeof(why)) != 0, "%s: taken", doc);
	ATF_CHECK_MSG(tag != NULL && strcmp(tag, want) == 0, "%s: %s, not %s "
	    "(%s)", doc, tag != NULL ? tag : "none", want, why);
	cbl_ybuf_free(&c);
}

ATF_TC_WITHOUT_HEAD(rfc7951);
ATF_TC_BODY(rfc7951, tc)
{
	struct cbl_ysids *s = view(tc, 0, NULL, 0);

	/* Section 4: a member's module said where it changes. */
	both_ways(s, "{\"example-foomod:top\":{\"foo\":54,"
	    "\"example-barmod:bar\":true}}", CBL_ALL);
	/* 5.3, 5.4: a leaf-list, a list. */
	both_ways(s, "{\"example-foomod:top\":{\"bars\":[true,false],"
	    "\"item\":[{\"name\":\"b\",\"count\":0,\"tag\":[\"x\",\"y\"]},"
	    "{\"name\":\"a\",\"count\":-123}]}}", CBL_ALL);
	/* 6.1: numbers, 64-bit ones and decimal64 strings. */
	both_ways(s, "{\"example-foomod:top\":{\"foo\":255,\"big\":"
	    "\"-9223372036854775808\",\"ubig\":\"18446744073709551615\","
	    "\"price\":\"-12.25\"}}", CBL_ALL);
	/* 6.2 to 6.9: a string, an enum, bits, binary, an identity of
	 * another module, empty. */
	both_ways(s, "{\"example-foomod:top\":"
	    "{\"text\":\"a \\\"b\\\"\\t\\u0001\","
	    "\"color\":\"green\",\"flags\":\"read execute\",\"blob\":\"AQID\","
	    "\"kind\":\"example-barmod:dog\",\"on\":[null]}}", CBL_ALL);
	/* 6.10: a union by its JSON kind, then by which member reads it. */
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":-7}}", CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":\"auto\"}}", CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":\"abc\"}}", CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":\"1234567890123\"}}",
	    CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":"
	    "\"example-foomod:cat\"}}", CBL_ALL);
	/* A string member's pattern matched in C.UTF-8, whatever the
	 * program's locale (C here): one character, two bytes. */
	both_ways(s, "{\"example-foomod:top\":{\"letter\":\"\xc3\xa9\"}}",
	    CBL_ALL);
	refused(s, "{\"example-foomod:top\":{\"letter\":\"ab\"}}",
	    "invalid-value");
	/* 6.11: an instance-identifier, which cblink's JSON has as null. */
	both_ways(s, "{\"example-foomod:top\":{\"where\":"
	    "\"/example-foomod:top/item[name='a']/count\"}}", CBL_JSON);
	both_ways(s, "{\"example-foomod:top\":{\"where\":"
	    "\"/example-foomod:top/example-barmod:bar\"}}", CBL_JSON);
	both_ways(s, "{\"example-foomod:top\":{\"where\":"
	    "\"/example-foomod:top/item[name=\\\"it's\\\"]/tag[.='x']\"}}",
	    CBL_JSON);
	/* A decimal64's canonical form has no zeros at its end (RFC 7950
	 * 9.3.2), which cblink's JSON keeps. */
	both_ways(s, "{\"example-foomod:top\":{\"price\":\"0.5\"}}", CBL_JSON);

	/* What is not: the errors RFC 8040 section 7 names. */
	refused(s, "{\"example-foomod:top\":{\"nope\":1}}", "unknown-element");
	refused(s, "{\"example-nomod:top\":{}}", "unknown-namespace");
	refused(s, "{\"top\":{}}", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":256}}", "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"color\":\"blue\"}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"mixed\":\"A-1\"}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"price\":\"1.234\"}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"on\":true}}", "invalid-value");
	cbl_ysids_free(s);
}

static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	atf_tc_fail("no %s under %s", name, n->name);
	return (NULL);
}

/* RFC 7952 section 5.2: a container's, an entry's, a leaf's and a
 * leaf-list entry's annotations, as cblink writes them in YANG-CBOR. */
ATF_TC_WITHOUT_HEAD(rfc7952);
ATF_TC_BODY(rfc7952, tc)
{
	static const char lmt[] = "2015-09-16T10:27:35+02:00";
	struct cbl_ysids		*s = view(tc, 0, NULL, 0);
	const struct cbl_ymodule *fm = NULL, *lm = NULL;
	const struct cbl_ynode	*top, *n;
	const struct cbl_yannot	*an;
	struct cbl_ybuf		 c = { NULL, 0, 0 }, j = { NULL, 0, 0 },
				 k = { NULL, 0, 0 };
	cbl_dtree		*t;
	cbl_dnode		*dt, *x;
	ucl_object_t		*got, *want;
	const char		*lp = lmt, *key = "a";
	uint8_t			 u8 = 42;
	bool			 tru = true, fls = false;
	char			 why[256], *out;

	for (uint32_t i = 0; i < yxtest_schema.nmod; i++) {
		if (strcmp(yxtest_schema.mod[i]->name, "example-foomod") == 0)
			fm = yxtest_schema.mod[i];
		if (strcmp(yxtest_schema.mod[i]->name,
		    "example-last-modified") == 0)
			lm = yxtest_schema.mod[i];
	}
	ATF_REQUIRE(fm != NULL && lm != NULL);
	ATF_REQUIRE((an = cbl_ymodule_annot(lm, "last-modified")) != NULL);
	top = fm->top[0];
	ATF_REQUIRE((t = cbl_dtree_new(&yxtest_schema)) != NULL);
	ATF_REQUIRE(cbl_dnode_add(cbl_dtree_root(t), top, NULL, &dt) == 0);
	ATF_REQUIRE(cbl_dnode_meta_set(dt, an, &lp) == 0);
	ATF_REQUIRE(cbl_dnode_add(dt, child(top, "foo"), &u8, &x) == 0);
	ATF_REQUIRE(cbl_dnode_meta_set(x, an, &lp) == 0);
	n = child(top, "bars");
	ATF_REQUIRE(cbl_dnode_add(dt, n, &tru, NULL) == 0);
	ATF_REQUIRE(cbl_dnode_add(dt, n, &fls, &x) == 0);
	ATF_REQUIRE(cbl_dnode_meta_set(x, an, &lp) == 0);
	{
		const void *keys[] = { &key };

		ATF_REQUIRE(cbl_dnode_add_entry(dt, child(top, "item"), keys,
		    &x) == 0);
		ATF_REQUIRE(cbl_dnode_meta_set(x, an, &lp) == 0);
	}
	ATF_REQUIRE(cbl_dtree_encode(t, &c) == 0);
	ATF_REQUIRE_MSG(cbl_yxlate_json(s, c.p, c.len, &j, why,
	    sizeof(why)) == 0, "%s", why);
	out = text(&j);
	printf("%s\n", out);
	got = json(out);
	want = json("{\"example-foomod:top\":{"
	    "\"@\":{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"},"
	    "\"foo\":42,\"@foo\":{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"},"
	    "\"bars\":[true,false],\"@bars\":[null,"
	    "{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"}],"
	    "\"item\":[{\"@\":{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"},\"name\":\"a\"}]}}");
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s", out);
	ucl_object_unref(got);
	free(out);
	/* cblink's JSON of the tree: the same shape. */
	ATF_REQUIRE(cbl_dtree_json(t, &k) == 0);
	out = text(&k);
	got = json(out);
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "cblink's: %s", out);
	ucl_object_unref(got);
	free(out);
	ucl_object_unref(want);
	cbl_dtree_free(t);
	cbl_ybuf_free(&c);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&k);
	cbl_ysids_free(s);
}

/*
 * A peer that numbers every item 500 on, and has a node the local
 * tables do not: its YANG-CBOR named and typed by its files, that node
 * as CBOR's kind says; the local numbering reads it as nothing.
 */
ATF_TC_WITHOUT_HEAD(peer_sids);
ATF_TC_BODY(peer_sids, tc)
{
	static const char doc[] = "{\"example-foomod:top\":{\"foo\":7,"
	    "\"kind\":\"example-foomod:cat\",\"where\":"
	    "\"/example-foomod:top/foo\"}}";
	struct cbl_ysids	*own = view(tc, 0, NULL, 0), *peer;
	const struct cbl_ysid_item *it;
	struct cbl_ybuf		 c = { NULL, 0, 0 }, j = { NULL, 0, 0 };
	ucl_object_t		*v, *got;
	const char		*tag;
	char			 why[256], *out;
	uint8_t			*p;

	peer = view(tc, 500, "/example-foomod:top/newer", 99599);
	ATF_REQUIRE((it = cbl_ysids_data(peer, "/example-foomod:top/foo")) !=
	    NULL);
	ATF_CHECK_EQ(99509, it->sid);
	ATF_CHECK(it->what != NULL && it->what == cbl_ysids_data(own,
	    "/example-foomod:top/foo")->what);
	ATF_REQUIRE((it = cbl_ysids_data(peer, "/example-foomod:top/newer")) !=
	    NULL);
	ATF_CHECK(it->what == NULL);
	ATF_CHECK_EQ(99503, it->base);
	both_ways(peer, doc, NO_CBLINK);
	ATF_REQUIRE(cbl_yxlate_cbor(peer, doc, strlen(doc), &c, &tag, why,
	    sizeof(why)) == 0);
	/* Read by the local numbering: SIDs it does not have. */
	ATF_CHECK(cbl_yxlate_json(own, c.p, c.len, &j, why, sizeof(why)) != 0);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&c);
	memset(&j, 0, sizeof(j));
	/* The peer's {top: {newer(+96): 5, foo(+6): 7}}, by hand. */
	p = (uint8_t[]){ 0xa1, 0x1a, 0x00, 0x01, 0x84, 0xaf, 0xa2, 0x18, 0x60,
	    0x05, 0x06, 0x07 };
	ATF_REQUIRE_MSG(cbl_yxlate_json(peer, p, 12, &j, why,
	    sizeof(why)) == 0, "%s", why);
	out = text(&j);
	got = json(out);
	v = json("{\"example-foomod:top\":{\"newer\":5,\"foo\":7}}");
	ATF_CHECK_MSG(ucl_object_compare(v, got) == 0, "%s", out);
	ucl_object_unref(v);
	ucl_object_unref(got);
	free(out);
	cbl_ybuf_free(&j);
	cbl_ysids_free(own);
	cbl_ysids_free(peer);
}

/*
 * One node's value each way (an action's input and output are read and
 * written so); JSON's escapes; what is not JSON refused as RFC 8040's
 * malformed-message, a .sid file too.
 */
ATF_TC_WITHOUT_HEAD(json_text);
ATF_TC_BODY(json_text, tc)
{
	static const char val[] = "{\"foo\":7,\"item\":[{\"name\":\"a\"}]}";
	static const char neg[] = "{\"module-name\":\"m\",\"item\":"
	    "[{\"namespace\":\"data\",\"identifier\":\"/m:a\","
	    "\"sid\":\"-1\"}]}";
	struct cbl_ysids	*s = view(tc, 0, NULL, 0), *e;
	const struct cbl_ysid_item *it;
	struct cbl_ybuf		 c = { NULL, 0, 0 }, j = { NULL, 0, 0 };
	ucl_object_t		*want, *got;
	const char		*tag;
	char			 why[256], deep[600], *out;
	bool			 first = true;

	ATF_REQUIRE((it = cbl_ysids_data(s, "/example-foomod:top")) != NULL);
	ATF_REQUIRE_MSG(cbl_yxlate_cbor_member(s, it, val, strlen(val), &c,
	    &tag, why, sizeof(why)) == 0, "%s %s", tag, why);
	ATF_REQUIRE(cbl_yxlate_json_member(s, it, c.p, c.len, &first, &j,
	    why, sizeof(why)) == 0);
	ATF_CHECK(!first);
	out = text(&j);
	ATF_CHECK_MSG(strncmp(out, "\"example-foomod:top\":", 21) == 0, "%s",
	    out);
	got = json(out + 21);
	want = json(val);
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s", out);
	ucl_object_unref(want);
	ucl_object_unref(got);
	free(out);
	cbl_ybuf_free(&c);
	cbl_ybuf_free(&j);
	/* A leaf's value alone; one not of its type. */
	ATF_REQUIRE((it = cbl_ysids_data(s, "/example-foomod:top/foo")) !=
	    NULL);
	ATF_REQUIRE(cbl_yxlate_cbor_member(s, it, " 7 ", 3, &c, &tag, why,
	    sizeof(why)) == 0);
	ATF_CHECK(c.len == 1 && c.p[0] == 0x07);
	cbl_ybuf_free(&c);
	ATF_CHECK(cbl_yxlate_cbor_member(s, it, "1e2", 3, &c, &tag, why,
	    sizeof(why)) != 0 && strcmp(tag, "invalid-value") == 0);
	cbl_ybuf_free(&c);

	/* Escapes, a surrogate pair among them, and UTF-8 as it is: the
	 * text string's bytes (libucl's reader keeps \/ and pairs apart,
	 * so not compared through it). */
	{
		static const char esc[] = "{\"example-foomod:top\":{\"text\":"
		    "\"\\ud83d\\ude00 \\u00e9 \xc3\xa9 \\/ \\\\ \\n\"}}";
		static const char want8[] = "\xf0\x9f\x98\x80 \xc3\xa9 "
		    "\xc3\xa9 / \\ \n";

		ATF_REQUIRE_MSG(cbl_yxlate_cbor(s, esc, strlen(esc), &c, &tag,
		    why, sizeof(why)) == 0, "%s", why);
		ATF_CHECK(memmem(c.p, c.len, want8, strlen(want8)) != NULL);
		ATF_REQUIRE(cbl_yxlate_json(s, c.p, c.len, &j, why,
		    sizeof(why)) == 0);
		out = text(&j);
		printf("%s\n", out);
		free(out);
		cbl_ybuf_free(&c);
		cbl_ybuf_free(&j);
	}

	refused(s, "", "malformed-message");
	refused(s, "{", "malformed-message");
	refused(s, "{\"example-foomod:top\":{}} x", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":1,\"foo\":2}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"text\":\"\xff\"}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"text\":\"\xc0\xaf\"}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"text\":\"\\ud800\"}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"text\":\"a\\u0000b\"}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"text\":\"a\tb\"}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":01}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":1.}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":1,}}",
	    "malformed-message");
	refused(s, "{'example-foomod:top':{}}", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"on\":[nul]}}",
	    "malformed-message");
	memset(deep, '[', sizeof(deep) - 1);
	deep[sizeof(deep) - 1] = '\0';
	refused(s, deep, "malformed-message");
	/* A number past int64 where a number is. */
	refused(s, "{\"example-foomod:top\":{\"foo\":99999999999999999999}}",
	    "invalid-value");

	ATF_REQUIRE((e = cbl_ysids_new(&yxtest_schema)) != NULL);
	ATF_CHECK(cbl_ysids_file_json(e, "{\"ietf-sid-file:sid-file\":", 26,
	    why, sizeof(why)) == EINVAL);
	ATF_CHECK(cbl_ysids_file_json(e, neg, strlen(neg), why,
	    sizeof(why)) == EINVAL);
	cbl_ysids_free(e);
	cbl_ysids_free(s);
}

/*
 * A member's name is one name: "item/count" (a path) refused, not taken
 * as the grandchild keyed by a delta from the wrong node; "x" and "m:x"
 * name one child, which may be there once.  A decimal64 given as a JSON
 * number read as its digits are, never through a double: 1.234 for two
 * fraction digits refused, not rounded.
 */
ATF_TC_WITHOUT_HEAD(member_names);
ATF_TC_BODY(member_names, tc)
{
	struct cbl_ysids	*s = view(tc, 0, NULL, 0);
	struct cbl_ybuf		 c = { NULL, 0, 0 };
	const struct cbl_ysid_item *it;
	const char		*tag = NULL;
	char			 why[256];
	static const char price[] = "{\"example-foomod:top\":"
	    "{\"price\":12.25}}";
	/* {top: {price's delta: 4([-2, 1225])}} */
	static const uint8_t want[] = { 0xc4, 0x82, 0x21, 0x19, 0x04, 0xc9 };

	refused(s, "{\"example-foomod:top\":{\"item/count\":5}}",
	    "malformed-message");
	refused(s, "{\"example-foomod:top/foo\":5}", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"\":5}}", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":1,"
	    "\"example-foomod:foo\":2}}", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"price\":1.234}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"price\":0.125}}",
	    "invalid-value");
	ATF_REQUIRE_MSG(cbl_yxlate_cbor(s, price, strlen(price), &c, &tag, why,
	    sizeof(why)) == 0, "%s %s", tag, why);
	ATF_CHECK(memmem(c.p, c.len, want, sizeof(want)) != NULL);
	cbl_ybuf_free(&c);
	/* The child of the node encoded keyed from it, the member form. */
	ATF_REQUIRE((it = cbl_ysids_data(s, "/example-foomod:top")) != NULL);
	ATF_CHECK(cbl_yxlate_cbor_member(s, it, "{\"item/count\":5}",
	    strlen("{\"item/count\":5}"), &c, &tag, why, sizeof(why)) != 0);
	cbl_ybuf_free(&c);
	cbl_ysids_free(s);
}

/*
 * .sid files: an item without its namespace refused (not taken as an
 * annotation); one path by two SIDs refused; an identifier with a NUL
 * in it refused.
 */
ATF_TC_WITHOUT_HEAD(sid_items);
ATF_TC_BODY(sid_items, tc)
{
	static const char nons[] = "{\"module-name\":\"m\",\"item\":"
	    "[{\"identifier\":\"/m:a\",\"sid\":\"5\"}]}";
	static const char two[] = "{\"module-name\":\"m\",\"item\":"
	    "[{\"namespace\":\"data\",\"identifier\":\"/m:a\","
	    "\"sid\":\"5\"},{\"namespace\":\"data\",\"identifier\":"
	    "\"/m:a\",\"sid\":\"6\"}]}";
	/* {module-name: "m", item: [{identifier: "/m:a", sid: 5}]}, as
	 * RFC 9595's YANG-CBOR: deltas from 1301, then from 1309. */
	static const uint8_t nons_cbor[] = { 0xa2, 0x0d, 0x61, 0x6d, 0x08,
	    0x81, 0xa2, 0x01, 0x64, 0x2f, 0x6d, 0x3a, 0x61, 0x03, 0x05 };
	/* The same, namespace data, its identifier "/m:a" NUL "x". */
	static const uint8_t nul_cbor[] = { 0xa2, 0x0d, 0x61, 0x6d, 0x08,
	    0x81, 0xa3, 0x01, 0x66, 0x2f, 0x6d, 0x3a, 0x61, 0x00, 0x78, 0x02,
	    0x03, 0x03, 0x05 };
	struct cbl_ysids	*e;
	char			 why[256];

	(void)tc;
	ATF_REQUIRE((e = cbl_ysids_new(&yxtest_schema)) != NULL);
	ATF_CHECK_EQ(EINVAL, cbl_ysids_file_json(e, nons, strlen(nons), why,
	    sizeof(why)));
	cbl_ysids_free(e);
	ATF_REQUIRE((e = cbl_ysids_new(&yxtest_schema)) != NULL);
	ATF_REQUIRE_EQ(0, cbl_ysids_file_json(e, two, strlen(two), why,
	    sizeof(why)));
	ATF_CHECK_EQ(EINVAL, cbl_ysids_done(e, why, sizeof(why)));
	ATF_CHECK_MSG(strstr(why, "two SIDs") != NULL, "%s", why);
	cbl_ysids_free(e);
	ATF_REQUIRE((e = cbl_ysids_new(&yxtest_schema)) != NULL);
	ATF_CHECK_EQ(EINVAL, cbl_ysids_file_cbor(e, nons_cbor,
	    sizeof(nons_cbor), why, sizeof(why)));
	cbl_ysids_free(e);
	ATF_REQUIRE((e = cbl_ysids_new(&yxtest_schema)) != NULL);
	ATF_CHECK_EQ(EINVAL, cbl_ysids_file_cbor(e, nul_cbor,
	    sizeof(nul_cbor), why, sizeof(why)));
	cbl_ysids_free(e);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc7951);
	ATF_TP_ADD_TC(tp, rfc7952);
	ATF_TP_ADD_TC(tp, peer_sids);
	ATF_TP_ADD_TC(tp, json_text);
	ATF_TP_ADD_TC(tp, member_names);
	ATF_TP_ADD_TC(tp, sid_items);
	return (atf_no_error());
}