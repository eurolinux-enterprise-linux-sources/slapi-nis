SUBDIRS = clients

noinst_PROGRAMS = wrappers.so
wrappers_so_SOURCES = wrap-nsswitch.c wrap-pam.c
wrappers_so_CFLAGS = $(AM_CFLAGS) -fPIC
wrappers_so_LDADD = -ldl
wrappers_so_LDFLAGS = -shared
wrappers_so_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(wrappers_so_LDFLAGS) $(LDFLAGS) -o $@

EXTRA_DIST = run-tests.sh test*/*.ldif test*/*.sh test*/*.txt *.supp \
	config/slapd-collations.conf config/userRoot.ldif config/schema \
	test36-schema-nsswitch/wrap_passwd.in

CLEANFILES = test36-schema-nsswitch/wrap_passwd
test36-schema-nsswitch/wrap_passwd: $(top_builddir)/config.status test36-schema-nsswitch/wrap_passwd.in
	cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@

if CAN_TEST
check: test36-schema-nsswitch/wrap_passwd
	@true
if NIS
	builddir=$(abs_builddir) \
	$(srcdir)/run-tests.sh $(srcdir)/test*-nis-*
endif
if SCHEMA
	builddir=$(abs_builddir) \
	$(srcdir)/run-tests.sh $(srcdir)/test*-schema-*
endif
endif
