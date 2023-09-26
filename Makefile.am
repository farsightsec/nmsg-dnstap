bin_PROGRAMS =
EXTRA_DIST =
TESTS =
CLEANFILES =
DISTCLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-I${top_srcdir}/cache \
	-I${top_srcdir}/util
AM_CFLAGS = \
	${my_CFLAGS} \
	$(libfstrm_CFLAGS) \
	$(libnmsg_CFLAGS) \
	$(libzmq_CFLAGS)
AM_LDFLAGS = -Wl,--as-needed

bin_PROGRAMS += src/nmsg-dnstap
src_nmsg_dnstap_LDADD = \
	$(libnmsg_LIBS) \
	$(libfstrm_LIBS) \
	$(libzmq_LIBS) \
	$(libevent_LIBS) \
	$(libevent_pthreads_LIBS)
src_nmsg_dnstap_SOURCES = \
	src/nmsg-dnstap.c \
	src/fstrm_srv.c \
	src/fstrm_srv.h \
	libmy/argv.c \
	libmy/argv.h \
	libmy/argv_loc.h \
	libmy/my_alloc.h \
	libmy/print_string.h

dist_man_MANS = man/nmsg-dnstap.1

AM_TESTS_ENVIRONMENT= abs_top_builddir='$(abs_top_builddir)' abs_top_srcdir='$(abs_top_srcdir)'

TESTS += tests/test-unix-domain-to-nmsg-udp-sock-pres.sh
TESTS += tests/test-tcp-to-nmsg-zeromq-json.sh

EXTRA_DIST += $(TESTS)

EXTRA_DIST += \
	tests/dnstap-input-data \
	tests/nmsgtool.dnstap.json \
	tests/nmsgtool.dnstap.pres

DISTCLEANFILES += tests/test-*.out
