EXTRA_DIST = COPYING NEWS README STATUS slapi-nis.spec doc/*.txt doc/examples/*.ldif.in doc/devel doc/ipa src/nisserver-plugin-defs.1 yp/yp.x
SUBDIRS = yp src tests
ACLOCAL_AMFLAGS=-I m4

noinst_DATA = $(builddir)/doc/nis-known-maps.txt
$(builddir)/doc/nis-known-maps.txt: src/defs-nis.c $(builddir)/Makefile
	: > $@
	echo "This is the list of NIS maps for which compiled-in default search" >> $@
	echo "filters and key and value format specifiers are currently known:" >> $@
	echo "" >> $@
	grep -E '^	{"[^"]+",' $(srcdir)/src/defs-nis.c | awk -F'"' '{print "   ", $$2}' >> $@

VERSION=@PACKAGE_VERSION@
RELEASE=0
GITTAG=slapi-nis-$(VERSION)
distdir=slapi-nis-$(VERSION)

tag:
	git tag $(GITTAG)

force-tag:
	git tag -f $(GITTAG)

ORIGIN=$(shell git config remote.origin.url 2> /dev/null || /bin/pwd)
ARCHIVEOUTDIR=$(shell cd $(top_srcdir) && pwd)

local-archive:
	$(MAKE) archive ORIGIN=$(ARCHIVEOUTDIR)

archive:
	repo=`pwd`; \
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`; \
	if test -d "$$tmpdir" ; then \
		git clone $(ORIGIN) $$tmpdir/slapi-nis;\
		cd $$tmpdir/slapi-nis;\
		git checkout $(GITTAG);\
		./autogen.sh;\
		make dist;\
		mkdir -p "$$tmpdir"/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi
