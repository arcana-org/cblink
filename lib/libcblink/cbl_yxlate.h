/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBL_YXLATE_H_
#define	_CBL_YXLATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cbl_schema.h>

/*
 * A schema's SIDs as a peer numbers them (cbl_ysid.c): the items of its
 * .sid files (RFC 9595), by SID and by identifier, each resolved to the
 * local tables' (types) node, identity or annotation of the same
 * identifier where they have one; and the modules its YANG library
 * (RFC 8525) says.  The translator below names and types by it.
 *
 * cbl_ysids_new(): an empty one over tables types;
 * cbl_ysids_file_cbor() adds a .sid file as GET-SID sends it (the
 * ietf-sid-file structure's value), cbl_ysids_file_json() as RFC 9595's
 * JSON has it ({"ietf-sid-file:sid-file": ...}, or its value),
 * cbl_ysids_tables() every item of the tables themselves (the local
 * numbering); cbl_ysids_module() a module of the library;
 * cbl_ysids_done() sorts and resolves them, after which it is read-only
 * and may be shared between threads.  0, or an errno and why.
 */
#define	CBL_YSID_NS_MODULE	0
#define	CBL_YSID_NS_IDENTITY	1
#define	CBL_YSID_NS_FEATURE	2
#define	CBL_YSID_NS_DATA	3
#define	CBL_YSID_NS_ANNOTATION	4	/* draft-ietf-core-yang-metadata's */

struct cbl_ysid_item {
	uint64_t	 sid;
	/* Data: the SID its key is a delta from, its parent's (an rpc's or
	 * an action's for what is in its input or output); 0 at the top. */
	uint64_t	 base;
	const char	*id;		/* as the file has it */
	const char	*module;	/* the file's */
	const char	*name;		/* the last name of id */
	const char	*nmod;		/* that name's module */
	/* The local struct cbl_ynode, cbl_yident or cbl_yannot of the same
	 * identifier, or of the module struct cbl_ymodule; NULL: the
	 * tables have none. */
	const void	*what;
	uint8_t		 ns;		/* CBL_YSID_NS_* */
	bool		 obsolete;
	bool		 io;		/* an input or an output */
	bool		 top;		/* data at the top of its module */
};

struct cbl_ysid_mod {
	const char	*name;
	const char	*revision;	/* "": none */
	bool		 implemented;	/* else imported only */
};

struct cbl_ysids;

struct cbl_ysids *cbl_ysids_new(const struct cbl_yschema *types);
void		 cbl_ysids_free(struct cbl_ysids *s);
int		 cbl_ysids_file_cbor(struct cbl_ysids *s, const void *cbor,
		    size_t len, char *why, size_t whylen);
int		 cbl_ysids_file_json(struct cbl_ysids *s, const char *json,
		    size_t len, char *why, size_t whylen);
int		 cbl_ysids_tables(struct cbl_ysids *s);
/* The modules skip says, and what is below their nodes, passed over by
 * all that adds after. */
void		 cbl_ysids_skip(struct cbl_ysids *s,
		    bool (*skip)(const struct cbl_ymodule *));
int		 cbl_ysids_module(struct cbl_ysids *s, const char *name,
		    const char *revision, bool implemented);
int		 cbl_ysids_set_content_id(struct cbl_ysids *s, const char *id);
int		 cbl_ysids_done(struct cbl_ysids *s, char *why, size_t whylen);

/*
 * Lookups: the item of a SID; a data node's by its schema-node path
 * ("/m:a/b/n:c"); an identity's, an annotation's, a feature's or a
 * module's by module and name; the item resolved to the local what.
 * NULL: none.  cbl_ysids_mod(): the library's module of that name,
 * NULL: none (or no library given); cbl_ysids_nmod() how many.
 */
const struct cbl_ysid_item *cbl_ysids_sid(const struct cbl_ysids *s,
		    uint64_t sid);
const struct cbl_ysid_item *cbl_ysids_data(const struct cbl_ysids *s,
		    const char *path);
const struct cbl_ysid_item *cbl_ysids_named(const struct cbl_ysids *s,
		    int ns, const char *module, const char *name);
const struct cbl_ysid_item *cbl_ysids_of(const struct cbl_ysids *s,
		    const void *what);
const struct cbl_ysid_mod *cbl_ysids_mod(const struct cbl_ysids *s,
		    const char *name);
size_t		 cbl_ysids_nmod(const struct cbl_ysids *s);
const struct cbl_ysid_mod *cbl_ysids_mod_at(const struct cbl_ysids *s,
		    size_t i);
const char	*cbl_ysids_content_id(const struct cbl_ysids *s);
size_t		 cbl_ysids_count(const struct cbl_ysids *s);
const struct cbl_yschema *cbl_ysids_types(const struct cbl_ysids *s);
/* The SIDs of its top-level data nodes, max at most, by SID: how many. */
size_t		 cbl_ysids_tops(const struct cbl_ysids *s, uint64_t *out,
		    size_t max);

/*
 * The schema-node path of node n (RFC 9595's identifier: each name
 * qualified where its module is not its parent's), in buf; false where
 * it does not fit.
 */
bool		 cbl_ysids_node_path(const struct cbl_ynode *n, char *buf,
		    size_t len);

/*
 * RFC 7951's JSON and RFC 9254's YANG-CBOR, each into the other by a
 * schema's SIDs as a peer numbers them (cbl_yxlate.c): names from its
 * .sid files, types from the local tables where they have the node.
 *
 * cbl_yxlate_json(): a map of top-level nodes keyed by their SIDs, as a
 * GET's reply or an EDIT has them, appended to b as one JSON object,
 * each member "module:name", annotations as RFC 7952 section 5.2 has
 * them.  cbl_yxlate_json_member(): one top-level node's value
 * (cbl_msg_sid_raw()'s), as a member "module:name": value, with a comma
 * before it unless *first.
 * cbl_yxlate_cbor(): a JSON text (len bytes) of an object of top-level
 * nodes made such a map; cbl_yxlate_cbor_member(): node it's JSON value
 * alone.  0, or an errno, why, and *tag the RFC 8040 error-tag
 * (unknown-element, unknown-namespace, invalid-value,
 * malformed-message, operation-not-supported).
 */
int		 cbl_yxlate_json(const struct cbl_ysids *s, const void *cbor,
		    size_t len, struct cbl_ybuf *b, char *why, size_t whylen);
int		 cbl_yxlate_json_member(const struct cbl_ysids *s,
		    const struct cbl_ysid_item *it, const void *cbor,
		    size_t len, bool *first, struct cbl_ybuf *b, char *why,
		    size_t whylen);
int		 cbl_yxlate_cbor(const struct cbl_ysids *s, const char *json,
		    size_t len, struct cbl_ybuf *b, const char **tag,
		    char *why, size_t whylen);
int		 cbl_yxlate_cbor_member(const struct cbl_ysids *s,
		    const struct cbl_ysid_item *it, const char *json,
		    size_t len, struct cbl_ybuf *b, const char **tag,
		    char *why, size_t whylen);
/* An instance-identifier's XPath (RFC 7951 section 6.11) as YANG-CBOR's
 * (RFC 9254 section 6.13.1): its SID, or [SID, keys...]. */
int		 cbl_yxlate_iid(const struct cbl_ysids *s, const char *path,
		    struct cbl_ybuf *b, char *why, size_t whylen);

/*
 * A CBOR reader of definite lengths: an item's head (major type, and its
 * argument: a length, an integer, a tag, a simple value), a text
 * string, an item passed over.  0, or EINVAL at what is not CBOR.
 */
struct cbl_ycrd {
	const uint8_t	*p;
	const uint8_t	*end;
};

int		 cbl_ycrd_head(struct cbl_ycrd *r, int *major, uint64_t *arg);
int		 cbl_ycrd_peek(const struct cbl_ycrd *r, int *major,
		    uint64_t *arg);
int		 cbl_ycrd_text(struct cbl_ycrd *r, const char **s, size_t *len);
int		 cbl_ycrd_skip(struct cbl_ycrd *r);

/* A CBOR head appended to b. */
int		 cbl_ybuf_head(struct cbl_ybuf *b, int major, uint64_t arg);

#endif	/* !_CBL_YXLATE_H_ */
