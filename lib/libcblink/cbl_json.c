/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * JSON read (RFC 8259): recursive descent into a tree in an arena.  A
 * level's values are gathered in a vector of the heap and copied into
 * the arena when it ends, so that what the arena holds is the tree
 * alone; its limit bounds what a text may make.  Member names are
 * checked once each object is read, sorted, for one given twice.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cblink.h"
#include "cbl_schema.h"
#include "cbl_json.h"

struct jrd {
	const char	*p;
	const char	*end;
	const char	*start;
	cbl_yarena	*a;
	char		*why;
	size_t		 whylen;
	int		 error;		/* ENOMEM once out of memory */
};

static int	value(struct jrd *, struct cbl_jv *, int);

static int
bad(struct jrd *r, const char *fmt, ...)
{
	va_list	ap;
	int	n;

	if (r->error != 0)
		return (r->error);
	if (r->why != NULL && r->whylen > 0) {
		n = snprintf(r->why, r->whylen, "JSON, at %zu: ",
		    (size_t)(r->p - r->start));
		if (n >= 0 && (size_t)n < r->whylen) {
			va_start(ap, fmt);
			(void)vsnprintf(r->why + n, r->whylen - (size_t)n, fmt,
			    ap);
			va_end(ap);
		}
	}
	return (r->error = EINVAL);
}

static int
nomem(struct jrd *r)
{

	return (r->error = ENOMEM);
}

static void
ws(struct jrd *r)
{

	while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' ||
	    *r->p == '\n' || *r->p == '\r'))
		r->p++;
}

static int
hex4(struct jrd *r, unsigned *u)
{

	*u = 0;
	if (r->end - r->p < 4)
		return (bad(r, "a \\u escape cut short"));
	for (int i = 0; i < 4; i++) {
		char c = *r->p++;

		*u <<= 4;
		if (c >= '0' && c <= '9')
			*u |= (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			*u |= (unsigned)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			*u |= (unsigned)(c - 'A' + 10);
		else
			return (bad(r, "a \\u escape not hex"));
	}
	return (0);
}

static char *
utf8_put(char *o, unsigned u)
{

	if (u < 0x80)
		*o++ = (char)u;
	else if (u < 0x800) {
		*o++ = (char)(0xc0 | u >> 6);
		*o++ = (char)(0x80 | (u & 0x3f));
	} else if (u < 0x10000) {
		*o++ = (char)(0xe0 | u >> 12);
		*o++ = (char)(0x80 | (u >> 6 & 0x3f));
		*o++ = (char)(0x80 | (u & 0x3f));
	} else {
		*o++ = (char)(0xf0 | u >> 18);
		*o++ = (char)(0x80 | (u >> 12 & 0x3f));
		*o++ = (char)(0x80 | (u >> 6 & 0x3f));
		*o++ = (char)(0x80 | (u & 0x3f));
	}
	return (o);
}

/* One UTF-8 character at r->p, well formed (RFC 3629): its length, 0
 * where it is not. */
static size_t
utf8_len(const unsigned char *p, const unsigned char *end)
{
	unsigned	u;
	size_t		n;

	if (p[0] < 0x80)
		return (1);
	if (p[0] >= 0xc2 && p[0] <= 0xdf)
		n = 2, u = p[0] & 0x1f;
	else if (p[0] >= 0xe0 && p[0] <= 0xef)
		n = 3, u = p[0] & 0x0f;
	else if (p[0] >= 0xf0 && p[0] <= 0xf4)
		n = 4, u = p[0] & 0x07;
	else
		return (0);
	if ((size_t)(end - p) < n)
		return (0);
	for (size_t i = 1; i < n; i++) {
		if ((p[i] & 0xc0) != 0x80)
			return (0);
		u = u << 6 | (p[i] & 0x3f);
	}
	if ((n == 3 && (u < 0x800 || (u >= 0xd800 && u <= 0xdfff))) ||
	    (n == 4 && (u < 0x10000 || u > 0x10ffff)))
		return (0);
	return (n);
}

/* A string at r->p (its quote): its text, unescaped, in the arena. */
static int
string(struct jrd *r, const char **out, size_t *outlen)
{
	const char	*q;
	char		*buf, *o;
	unsigned	 u, lo;
	size_t		 n;

	r->p++;
	/* Its end first: what it unescapes to is never longer. */
	for (q = r->p; q < r->end && *q != '"'; q++)
		if (*q == '\\' && ++q == r->end)
			break;
	if (q >= r->end)
		return (bad(r, "a string not ended"));
	if ((buf = cbl_yarena_alloc(r->a, (size_t)(q - r->p) + 1)) == NULL)
		return (nomem(r));
	o = buf;
	while (r->p < q) {
		unsigned char c = (unsigned char)*r->p;

		if (c < 0x20)
			return (bad(r, "a control character in a string"));
		if (c != '\\') {
			if ((n = utf8_len((const unsigned char *)r->p,
			    (const unsigned char *)q)) == 0)
				return (bad(r, "a string not UTF-8"));
			memcpy(o, r->p, n);
			o += n;
			r->p += n;
			continue;
		}
		r->p++;
		switch (*r->p++) {
		case '"':  *o++ = '"'; break;
		case '\\': *o++ = '\\'; break;
		case '/':  *o++ = '/'; break;
		case 'b':  *o++ = '\b'; break;
		case 'f':  *o++ = '\f'; break;
		case 'n':  *o++ = '\n'; break;
		case 'r':  *o++ = '\r'; break;
		case 't':  *o++ = '\t'; break;
		case 'u':
			if (hex4(r, &u) != 0)
				return (r->error);
			if (u >= 0xdc00 && u <= 0xdfff)
				return (bad(r, "a low surrogate alone"));
			if (u >= 0xd800 && u <= 0xdbff) {
				if (q - r->p < 6 || r->p[0] != '\\' ||
				    r->p[1] != 'u')
					return (bad(r, "a high surrogate "
					    "alone"));
				r->p += 2;
				if (hex4(r, &lo) != 0)
					return (r->error);
				if (lo < 0xdc00 || lo > 0xdfff)
					return (bad(r, "a high surrogate "
					    "alone"));
				u = 0x10000 + ((u - 0xd800) << 10) +
				    (lo - 0xdc00);
			}
			if (u == 0)
				return (bad(r, "a NUL in a string"));
			o = utf8_put(o, u);
			break;
		default:
			r->p--;
			return (bad(r, "an escape JSON has not"));
		}
	}
	*o = '\0';
	r->p = q + 1;
	*out = buf;
	*outlen = (size_t)(o - buf);
	return (0);
}

static int
number(struct jrd *r, struct cbl_jv *v)
{
	const char	*s = r->p;
	char		*t;
	bool		 frac = false;

	if (r->p < r->end && *r->p == '-')
		r->p++;
	if (r->p == r->end || *r->p < '0' || *r->p > '9')
		return (bad(r, "not a number"));
	if (*r->p == '0')
		r->p++;
	else
		while (r->p < r->end && *r->p >= '0' && *r->p <= '9')
			r->p++;
	if (r->p < r->end && *r->p == '.') {
		r->p++;
		frac = true;
		if (r->p == r->end || *r->p < '0' || *r->p > '9')
			return (bad(r, "a fraction without digits"));
		while (r->p < r->end && *r->p >= '0' && *r->p <= '9')
			r->p++;
	}
	if (r->p < r->end && (*r->p == 'e' || *r->p == 'E')) {
		r->p++;
		frac = true;
		if (r->p < r->end && (*r->p == '+' || *r->p == '-'))
			r->p++;
		if (r->p == r->end || *r->p < '0' || *r->p > '9')
			return (bad(r, "an exponent without digits"));
		while (r->p < r->end && *r->p >= '0' && *r->p <= '9')
			r->p++;
	}
	if ((t = cbl_yarena_alloc(r->a, (size_t)(r->p - s) + 1)) == NULL)
		return (nomem(r));
	memcpy(t, s, (size_t)(r->p - s));
	v->s = t;
	v->len = (size_t)(r->p - s);
	v->type = frac ? CBL_JNUM : CBL_JINT;
	return (0);
}

static bool
word(struct jrd *r, const char *w)
{
	size_t	n = strlen(w);

	if ((size_t)(r->end - r->p) < n || memcmp(r->p, w, n) != 0)
		return (false);
	r->p += n;
	return (true);
}

static int
by_key(const void *a, const void *b)
{
	const struct cbl_jv *x = *(const struct cbl_jv *const *)a;
	const struct cbl_jv *y = *(const struct cbl_jv *const *)b;

	return (strcmp(x->key, y->key));
}

/* An array's elements or an object's members, r->p past its bracket. */
static int
items(struct jrd *r, struct cbl_jv *v, bool obj, int depth)
{
	struct cbl_jv	*vec = NULL, *nv, e;
	const struct cbl_jv **ix;
	size_t		 n = 0, cap = 0;
	int		 error = 0;
	char		 close = obj ? '}' : ']';

	ws(r);
	if (r->p < r->end && *r->p == close) {
		r->p++;
		return (0);
	}
	for (;;) {
		memset(&e, 0, sizeof(e));
		ws(r);
		if (obj) {
			if (r->p == r->end || *r->p != '"') {
				error = bad(r, "a member without its name");
				break;
			}
			if ((error = string(r, &e.key, &e.len)) != 0)
				break;
			ws(r);
			if (r->p == r->end || *r->p != ':') {
				error = bad(r, "a member without ':'");
				break;
			}
			r->p++;
			e.len = 0;
		}
		if ((error = value(r, &e, depth + 1)) != 0)
			break;
		if (n == cap) {
			cap = cap > 0 ? cap * 2 : 8;
			if ((nv = reallocarray(vec, cap, sizeof(*vec))) ==
			    NULL) {
				error = nomem(r);
				break;
			}
			vec = nv;
		}
		vec[n++] = e;
		ws(r);
		if (r->p < r->end && *r->p == ',') {
			r->p++;
			continue;
		}
		if (r->p < r->end && *r->p == close) {
			r->p++;
			break;
		}
		error = bad(r, "'%c' or ',' wanted", close);
		break;
	}
	if (error == 0 && (v->v = cbl_yarena_alloc(r->a, n *
	    sizeof(*vec))) == NULL)
		error = nomem(r);
	if (error == 0) {
		memcpy(v->v, vec, n * sizeof(*vec));
		v->n = n;
	}
	free(vec);
	if (error != 0 || !obj || n < 2)
		return (error);
	/* A member name twice: not JSON a YANG peer sends (RFC 7951 4). */
	if ((ix = calloc(n, sizeof(*ix))) == NULL)
		return (nomem(r));
	for (size_t i = 0; i < n; i++)
		ix[i] = &v->v[i];
	qsort(ix, n, sizeof(*ix), by_key);
	for (size_t i = 1; error == 0 && i < n; i++)
		if (strcmp(ix[i - 1]->key, ix[i]->key) == 0)
			error = bad(r, "member \"%s\" twice", ix[i]->key);
	free(ix);
	return (error);
}

static int
value(struct jrd *r, struct cbl_jv *v, int depth)
{

	if (depth > CBL_JSON_DEPTH)
		return (bad(r, "nested too deep"));
	ws(r);
	if (r->p == r->end)
		return (bad(r, "a value wanted"));
	switch (*r->p) {
	case '{':
	case '[':
		v->type = *r->p == '{' ? CBL_JOBJ : CBL_JARR;
		r->p++;
		return (items(r, v, v->type == CBL_JOBJ, depth));
	case '"':
		v->type = CBL_JSTR;
		return (string(r, &v->s, &v->len));
	case 't':
	case 'f':
		if (!word(r, "true") && !word(r, "false"))
			break;
		v->type = CBL_JBOOL;
		v->b = r->p[-1] == 'e' && r->p[-2] == 'u';
		v->s = v->b ? "true" : "false";
		v->len = strlen(v->s);
		return (0);
	case 'n':
		if (!word(r, "null"))
			break;
		v->type = CBL_JNULL;
		return (0);
	default:
		return (number(r, v));
	}
	return (bad(r, "not a value"));
}

int
cbl_json_parse(cbl_yarena *a, const char *text, size_t len,
    const struct cbl_jv **out, char *why, size_t whylen)
{
	struct jrd	 r = { text, text + len, text, a, why, whylen, 0 };
	struct cbl_jv	*v;

	*out = NULL;
	if (text == NULL)
		return (bad(&r, "none"));
	if ((v = cbl_yarena_alloc(a, sizeof(*v))) == NULL)
		return (ENOMEM);
	if (value(&r, v, 0) != 0)
		return (r.error);
	ws(&r);
	if (r.p != r.end)
		return (bad(&r, "more after the value"));
	*out = v;
	return (0);
}

const struct cbl_jv *
cbl_json_get(const struct cbl_jv *o, const char *key)
{

	if (o == NULL || o->type != CBL_JOBJ)
		return (NULL);
	for (size_t i = 0; i < o->n; i++)
		if (strcmp(o->v[i].key, key) == 0)
			return (&o->v[i]);
	return (NULL);
}

const char *
cbl_json_str(const struct cbl_jv *v)
{

	return (v != NULL && v->type == CBL_JSTR ? v->s : NULL);
}
