AC_PREREQ(2.64)
AC_INIT([nmsg-dnstap], [0.1.0])
AC_CONFIG_SRCDIR([src/nmsg-dnstap.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AM_SILENT_RULES([yes])
AC_PROG_CC_STDC
AC_SYS_LARGEFILE
PKG_PROG_PKG_CONFIG

my_CFLAGS="-D_GNU_SOURCE=1 -Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

PKG_CHECK_MODULES([libnmsg],    [libnmsg >= 1.1.1])
PKG_CHECK_MODULES([libfstrm],   [libfstrm >= 0.6.1])
PKG_CHECK_MODULES([libzmq],     [libzmq >= 4.0.0])
PKG_CHECK_MODULES([libevent],   [libevent >= 2])
PKG_CHECK_MODULES([libevent_pthreads],   [libevent_pthreads >= 2])

AC_CHECK_HEADERS([nmsg/sie/defs.h nmsg/sie/dnsdedupe.pb-c.h])

AX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
])

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
])
