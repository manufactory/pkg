pkg_common_cflags=	-I$(top_srcdir)/libpkg -I$(top_builddir)/libpkg \
			-I$(top_srcdir)/compat \
			-I$(top_srcdir)/external/libsbuf \
			@LDNS_CFLAGS@ \
			-I$(top_srcdir)/external/expat/lib \
			-I$(top_srcdir)/external/libucl/include \
			-I$(top_srcdir)/external/libucl/klib \
			-I$(top_srcdir)/external/uthash \
			-I$(top_srcdir)/external/sqlite \
			-Wno-pointer-sign

librepo_linux_deb_la_SOURCES=	linux_deb.c \
							common.c \
							fetch.c \
							init.c \
							query.c \
							update.c \
							util.c
librepo_linux_deb_la_CFLAGS=	$(pkg_common_cflags) -shared

librepo_linux_deb_static_la_LDFLAGS=	-all-static
librepo_linux_deb_static_la_SOURCES=	$(librepo_linux_deb_la_SOURCES)
librepo_linux_deb_static_la_CFLAGS=	$(pkg_common_cflags) -static

DYNLIBS=		librepo_linux_deb.la
noinst_LTLIBRARIES= librepo_linux_deb_static.la
if DYNAMIC
noinst_LTLIBRARIES+=	$(DYNLIBS)
endif

noinst_HEADERS=		linux_deb.h linux_deb_private.h util.h
