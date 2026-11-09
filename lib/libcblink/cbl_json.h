/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _CBL_JSON_H_
#define	_CBL_JSON_H_

/*
 * JSON read (RFC 8259), the library's own: a value made a tree in an
 * arena, for the translator (cbl_yxlate.c) and the .sid files in JSON
 * (cbl_ysid.c).  Strict: one value, UTF-8, no member name twice in an
 * object, no NUL in a string, at most CBL_JSON_DEPTH deep.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	CBL_JSON_DEPTH	128

enum {
	CBL_JNULL,
	CBL_JBOOL,
	CBL_JINT,		/* a number without fraction or exponent */
	CBL_JNUM,		/* a number with either */
	CBL_JSTR,
	CBL_JARR,
	CBL_JOBJ
};

struct cbl_jv {
	const char	*key;	/* a member's name; NULL else */
	/* A string's text, NUL-terminated; a number as it is written. */
	const char	*s;
	size_t		 len;	/* of s */
	struct cbl_jv	*v;	/* an array's elements, an object's members */
	size_t		 n;	/* how many */
	uint8_t		 type;	/* CBL_J* */
	bool		 b;	/* a boolean's value */
};

struct cbl_yarena;

/*
 * text (len bytes) read into *out, all of it a's: 0, or EINVAL and why,
 * or ENOMEM.  cbl_json_get(): object o's member key, NULL: none (or o
 * not an object); cbl_json_str(): v's string, NULL: v not a string.
 */
int		 cbl_json_parse(struct cbl_yarena *a, const char *text,
		    size_t len, const struct cbl_jv **out, char *why,
		    size_t whylen);
const struct cbl_jv *cbl_json_get(const struct cbl_jv *o, const char *key);
const char	*cbl_json_str(const struct cbl_jv *v);

#endif	/* !_CBL_JSON_H_ */
