AM_CFLAGS = $(LDAP_CFLAGS) $(RUNTIME_CFLAGS) $(TIRPC_CFLAGS) $(RPC_CFLAGS)
AM_LDFLAGS = -module -avoid-version -export-symbols-regex '.*_plugin_init'
LIBPTHREAD = @LIBPTHREAD@
LIBWRAP = @LIBWRAP@
CONFIGURED_LINK_FLAGS = @CONFIGURED_LINK_FLAGS@

plugindir = $(libdir)/dirsrv/plugins

plugin_LTLIBRARIES =
if NIS
plugin_LTLIBRARIES += nisserver-plugin.la
else
endif
if SCHEMA
plugin_LTLIBRARIES += schemacompat-plugin.la
endif

sbin_PROGRAMS = nisserver-plugin-defs
nisserver_plugin_defs_CFLAGS = $(AM_CFLAGS) -DDEFS_NIS_MAIN
nisserver_plugin_defs_SOURCES = defs-nis.c

man_MANS = nisserver-plugin-defs.1

noinst_PROGRAMS = portmap
portmap_CFLAGS = $(AM_CFLAGS) -DPORTMAP_MAIN
portmap_SOURCES = portmap.c
portmap_LDFLAGS = $(LDAP_LIBS) $(RUNTIME_LIBS) $(TIRPC_LIBS) $(LIBWRAP) $(RPC_LIBS) $(LIBPTHREAD)

nisserver_plugin_la_SOURCES = \
	back-nis.c \
	backend.h \
	back-shr.c \
	back-shr.h \
	defs-nis.c \
	defs-nis.h \
	disp-nis.c \
	disp-nis.h \
	format.c \
	format.h \
	map.c \
	map.h \
	nis.c \
	nis.h \
	plug-nis.c \
	plugin.h \
	portmap.c \
	portmap.h \
	wrap.c \
	wrap.h
nisserver_plugin_la_LIBADD = $(LDAP_LIBS) $(RUNTIME_LIBS) $(TIRPC_LIBS) $(LIBWRAP) $(RPC_LIBS) $(LIBPTHREAD) $(CONFIGURED_LINK_FLAGS)

schemacompat_plugin_la_SOURCES = \
	back-sch.c \
	backend.h \
	back-shr.c \
	back-shr.h \
	format.c \
	format.h \
	map.c \
	map.h \
	plug-sch.c \
	plugin.h \
	wrap.c \
	wrap.h
schemacompat_plugin_la_LIBADD = $(LDAP_LIBS) $(RUNTIME_LIBS) $(LIBPTHREAD) $(CONFIGURED_LINK_FLAGS)

noinst_LTLIBRARIES = dummy-nis-plugin.la
dummy_nis_plugin_la_SOURCES = \
	disp-nis.c \
	disp-nis.h \
	dummymap.c \
	map.h \
	nis.c \
	nis.h \
	plug-nis.c \
	plugin.h \
	portmap.c \
	portmap.h
dummy_nis_plugin_la_LIBADD = $(LDAP_LIBS) $(RUNTIME_LIBS) -lnsl -lpthread
