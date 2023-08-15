bin_PROGRAMS =
EXTRA_DIST =
CLEANFILES =
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

man_MANS = man/nmsg-dnstap.1
