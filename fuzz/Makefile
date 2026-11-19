# libFuzzer harnesses for the parsers that see untrusted input: frames
# alone (fuzz_frame) and as a connection's byte stream (fuzz_conn), PROXY
# protocol headers, YANG-CBOR into a module's structs (fuzz_ycodec), RFC
# 7951 JSON and .sid files (fuzz_yjson), instance-identifiers and the
# other paths (fuzz_iid), XPath and patterns.  The YANG ones go by the
# committed tables of cblink-gen's test module shapes (make regen).  Not
# part of the normal build ("make fuzz" at the top builds them, in
# obj/fuzz); the sources they test are compiled in, with coverage
# instrumentation and ASan/UBSan.  README says how to run them.

LIB=		${.CURDIR}/../lib/libcblink
.PATH:		${LIB}

LIBSRCS!=	cd ${LIB} && echo cbl_*.c

PROGS=		fuzz_frame fuzz_conn fuzz_proxy fuzz_ycodec fuzz_yjson \
		fuzz_iid fuzz_xpath fuzz_pattern
SRCS.fuzz_frame=	fuzz_frame.c ${LIBSRCS}
SRCS.fuzz_conn=	fuzz_conn.c ${LIBSRCS}
SRCS.fuzz_proxy=	fuzz_proxy.c ${LIBSRCS}
SRCS.fuzz_ycodec=	fuzz_ycodec.c yshapes_schema.c ${LIBSRCS}
SRCS.fuzz_yjson=	fuzz_yjson.c yshapes_schema.c ${LIBSRCS}
SRCS.fuzz_iid=	fuzz_iid.c yshapes_schema.c ${LIBSRCS}
SRCS.fuzz_xpath=	fuzz_xpath.c yshapes_schema.c ${LIBSRCS}
SRCS.fuzz_pattern=	fuzz_pattern.c cbl_pattern.c
MAN=

LOCALBASE?=	/usr/local
CSTD=		c23
WARNS?=		6
SANITIZE=	-fsanitize=fuzzer,address,undefined
CFLAGS+=	-g -O1 ${SANITIZE} -I${LIB} \
		-idirafter ${LOCALBASE}/include
LDFLAGS+=	${SANITIZE}
LIBS_CBLINK=	${LOCALBASE}/lib/libcbor.so -lssl -lcrypto -lpthread
LDADD.fuzz_frame=	${LIBS_CBLINK}
LDADD.fuzz_conn=	${LIBS_CBLINK}
LDADD.fuzz_proxy=	${LIBS_CBLINK}
LDADD.fuzz_ycodec=	${LIBS_CBLINK}
LDADD.fuzz_yjson=	${LIBS_CBLINK}
LDADD.fuzz_iid=	${LIBS_CBLINK}
LDADD.fuzz_xpath=	${LIBS_CBLINK}

# The tables fuzz_ycodec decodes by, committed: the fuzzers are built
# without cblink-gen.  make regen remakes them with the one built, and
# cblink_gen_test:ymod_regen fails when they differ.
SHAPES=		${.CURDIR}/../usr.bin/cblink-gen/tests/yang/shapes@2026-10-13
CBLINK_GEN?=	${.OBJDIR:H}/usr.bin/cblink-gen/cblink-gen
regen: .PHONY
	${CBLINK_GEN} -m h,schema -b yshapes -o ${.CURDIR} \
	    -s ${SHAPES}.sid ${SHAPES}.yang

.include <bsd.progs.mk>
