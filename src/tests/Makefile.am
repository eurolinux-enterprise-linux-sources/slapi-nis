SUBDIRS = clients
EXTRA_DIST = run-tests.sh test*/*.ldif test*/*.sh test*/*.txt config/slapd-collations.conf config/userRoot.ldif config/schema *.supp
if CAN_TEST
check:
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
