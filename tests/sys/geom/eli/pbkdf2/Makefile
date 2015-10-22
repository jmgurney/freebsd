# $FreeBSD$

.include <bsd.own.mk>

SYSDIR = ../../../../../sys
.PATH: ${SYSDIR}/geom/eli
.PATH: ${SYSDIR}/crypto/sha2

TESTSDIR=	${TESTBASE}/sys/geom/eli/pbkdf2

ATF_TESTS_C=	pbkdf2

CFLAGS.pbkdf2=	-I${SYSDIR}

SRCS.pbkdf2=	\
		hmactest.c \
		g_eli_crypto.c \
		pkcs5v2.c \
		sha2.c \
		sha256c.c

LIBADD.pbkdf2= crypto

testvect.h:	gentestvect.py
	python gentestvect.py > $@

.include <bsd.test.mk>
