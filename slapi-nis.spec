%if 0%{?fedora} >= 14 || 0%{?rhel} >= 6
%define ldap_impl openldap
%else
%define ldap_impl mozldap
%endif

Name:		slapi-nis
Version:	0.40
Release:	7%{?dist}
Summary:	NIS Server and Schema Compatibility plugins for Directory Server
Group:		System Environment/Daemons
License:	GPLv2
URL:		http://slapi-nis.fedorahosted.org/
Source0:	https://fedorahosted.org/releases/s/l/slapi-nis/slapi-nis-%{version}.tar.gz
Source1:	https://fedorahosted.org/releases/s/l/slapi-nis/slapi-nis-%{version}.tar.gz.sig
Patch0:		slapi-nis-0.40-leak.patch
Patch1:		slapi-nis-0.40-notxns.patch
Patch2:		slapi-nis-0.40-xdrfree.patch
Patch3:		slapi-nis-0.40-multiplex.patch
Patch4:		slapi-nis-0.40-xdrfree2.patch
Patch5:		slapi-nis-0.40-entryaddremove.patch
Patch6:		slapi-nis-memmove.patch
Patch7:		slapi-nis-lock-out-accounts-if-nsAccountLock-is-TRUE.patch

BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:	389-ds-base-devel >= 1.2.10, %{ldap_impl}-devel
BuildRequires:	autoconf, automake, libtool
Requires: 389-ds-base >= 1.2.10
BuildRequires:	nspr-devel, nss-devel, /usr/bin/rpcgen
%if 0%{?fedora} > 6 || 0%{?rhel} > 5
BuildRequires: tcp_wrappers-devel
%else
BuildRequires: tcp_wrappers
%endif
%if 0%{?fedora} > 14 || 0%{?rhel} > 6
BuildRequires:	libtirpc-devel
%endif
%if 0%{?rhel} > 0
ExclusiveArch:	x86_64 %{ix86}
%endif

%description
This package provides two plugins for Red Hat and 389 Directory Server.

The NIS Server plugin allows the directory server to act as a NIS server
for clients, dynamically generating and updating NIS maps according to
its configuration and the contents of the DIT, and serving the results to
clients using the NIS protocol as if it were an ordinary NIS server.

The Schema Compatibility plugin allows the directory server to provide an
alternate view of entries stored in part of the DIT, optionally adding,
dropping, or renaming attribute values, and optionally retrieving values
for attributes from multiple entries in the tree.

%prep
%setup -q
%patch0 -p1 -b .leak
%patch1 -p1 -b .notxns
%patch2 -p1 -b .xdrfree
%patch3 -p1 -b .multiplex
%patch4 -p1 -b .xdrfree2
%patch5 -p1 -b .entryaddremove
%patch6 -p1 -b .memmove
%patch7 -p1 -b .nsaccountlock

autoreconf -f -i

%build
%configure --disable-static --with-tcp-wrappers --with-ldap=%{ldap_impl}
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm $RPM_BUILD_ROOT/%{_libdir}/dirsrv/plugins/*.la

%if 0
# ns-slapd doesn't want to start in koji, so no tests get run
%check
make check
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc COPYING NEWS README STATUS doc/*.txt doc/examples/*.ldif
%{_mandir}/man1/*
%{_libdir}/dirsrv/plugins/*.so
%{_sbindir}/nisserver-plugin-defs

%changelog
* Tue Jan 19 2016 Alexander Bokovoy <abokovoy@redhat.com> - 0.40-7
- Add '!!' in front of encrypted password in NIS maps 
  if account in question is locked (#1298478)

* Tue Mar 25 2014 Nalin Dahyabhai <nalin@redhat.com> - 0.40-6
- backport fix to not ignore modifications that affect whether or not an
  entry shows up in a compat map (#1056648)
- backport fix to avoid potential crashes on domain or map removal (#1043639)

* Tue Dec 10 2013 Nalin Dahyabhai <nalin@redhat.com> - 0.40-5
- backport fix for an additional leak parsing the contents of a yp_all()
  request (#1039942)

* Thu Jul 25 2013 Nalin Dahyabhai <nalin@redhat.com> - 0.40-4
- backport fix for request argument memory leaks in NIS server (#967468)
- backport fix for dispatching for multiple connected clients in the NIS
  plugin (#923336)

* Fri Aug 24 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.40-3
- backport fix for a slow memory leak (#840926)
- tweak configure to disable explicit (wrong) transaction support (#829502)

* Wed Jun  6 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.40-2
- add explicit build-time and install-time dependencies on 389-ds-base 1.2.10,
  so that we know we build with transaction support (#829502)

* Fri Mar 30 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.40-1
- treat padding values passed to the "link" function as expressions to be
  evaluated rather than simply as literal values (part of #767372)

* Wed Mar 28 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.39-1
- add a "default" function for trying to evaluate one expression, then
  another, then another... (part of #767372)
- when creating a compat entry based on a real entry, set an entryUSN based on
  the source entry or the rootDSE (freeipa #864); the "scaffolding" entries
  won't have them

* Tue Mar  6 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.38-1
- properly escape RDN values when building compat entries (#796509, #800625)

* Mon Feb 13 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.37-1
- fix a compile error on systems where LDAP_SCOPE_SUBORDINATE isn't defined
  (reported by Christian Neuhold)
- conditionalize whether we have a build dependency on tcp_wrappers (older
  releases) or tcp_wrappers-devel (newer releases)

* Tue Jan 24 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.36-1
- take steps to avoid making yp_first/yp_next clients loop indefinitely
  when a single LDAP entry produces multiple copies of the same NIS key
  for a given map

* Tue Jan 24 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.35-1
- add mmatch/mregmatch[i]/mregsub[i] formatting functions which work like
  match/regmatch[i]/regsub[i], but which can handle and return lists of
  zero or more results (part of #783274)

* Thu Jan 19 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.34-1
- do entry comparisons ourselves, albeit less throughly, to avoid the worst
  case in pathological cases (more of #771444)

* Tue Jan 17 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.33-1
- get more aggressive about skipping unnecessary calculations (most of
  the problem in #771444, though not the approach described there)

* Mon Jan 16 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.32-1
- add support for directory server transactions (#758830,#766320)

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.28-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Wed Jan 11 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.31-1
- fix some memory leaks (more of #771493)

* Tue Jan 10 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.30-1
- skip recalculations when the attributes which changed don't factor into
  our calculations (part of #771493)

* Wed Jan  4 2012 Nalin Dahyabhai <nalin@redhat.com> - 0.29-1
- add regmatchi/regsubi formatting functions which work like regmatch/regsub,
  but do matching in a case-insensitive manner
- update NIS map defaults to match {CRYPT} userPassword values in a
  case-insensitive manner so that we also use {crypt} userPassword values
- fix inconsistencies in the NIS service stemming from using not-normalized DNs
  in some places where it should have used normalized DNs

* Mon Dec 19 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.28-1
- when configured with --with-ldap=openldap, link with -lldap_r rather
  than -lldap (rmeggins, #769107)

* Tue Dec  6 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.27-1
- when building for 389-ds, use Slapi_RWLocks if they appear to be available
  (the rest of #730394/#730403)

* Fri Aug 12 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.26-1
- when building for 389-ds, use libpthread's read-write locks instead of
  NSPR's (part of #730394/#730403)

* Wed Jul 27 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.25-1
- speed up building compat entries which reference thousands of other entries
  (more of #694623)
- 389-ds-base is apparently exclusive to x86_64 and %%{ix86} on EL, so we have
  to be, too

* Fri May 13 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.24-1
- carry our own yp.x, so that we don't get bitten if libc doesn't include
  yp client routines
- we need rpcgen at build-time now

* Thu Mar 31 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.23-1
- speed up building compat entries with attributes with thousands of literal
  values (#692690)

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.22-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Thu Jan  6 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.22-1
- fix a number of scanner-uncovered defects

* Thu Jan  6 2011 Nalin Dahyabhai <nalin@redhat.com> - 0.21-2
- make sure we always pull in nss-devel and nspr-devel, and the right
  ldap toolkit for the Fedora or RHEL version

* Tue Nov 18 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.21-1
- update to 0.21
  - schema-compat: don't look at standalone compat containers for a search,
    since we'll already have looked at the group container

* Tue Nov 18 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.20-1
- update to 0.20
  - add a deref_f function

* Mon Nov 17 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.19-1
- fix a brown-paper-bag crash

* Mon Nov 17 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.18-1
- update to 0.18
  - add a deref_rf function
  - schema-compat: don't respond to search requests for which there's no backend
  - schema-compat: add the ability to do standalone compat containers

* Wed Nov 17 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.17-6
- revert that last change, it's unnecessary

* Thu Nov 11 2010 Nalin Dahyabhai <nalin@redhat.com> - 0.17-5
- build against either 389-ds-base or redhat-ds-base, whichever is probably
  more appropriate here

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.17-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Wed Jul 15 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.17-3
- change buildreq from fedora-ds-base-devel to 389-ds-base-devel, which
  should avoid multilib conflicts from installing both arches of the new
  package (#511504)

* Tue Jul 14 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.17-2
- fixup changelog entries that resemble possible macro invocations

* Thu May 14 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.17-1
- actually send portmap registrations to the right server

* Thu May 14 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.16-1
- fix NIS server startup problem when no port is explicitly configured and
  we're using portmap instead of rpcbind (#500903)

* Fri May  8 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.15-1
- fix %%deref and %%referred to fail rather than return a valid-but-empty
  result when they fail to evaluate (reported by Rob Crittenden)

* Wed May  6 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.14-1
- correctly handle being loaded but disabled (#499404)

* Thu Apr 30 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.13-1
- update to 0.13, reworking %%link() to correct some bugs (#498432)

* Thu Apr 30 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.12-1
- correct test suite failures that 0.11 started triggering

* Tue Apr 28 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.11-1
- update to 0.11 (#497904)

* Wed Mar  4 2009 Nalin Dahyabhai <nalin@redhat.com> - 0.10-1
- update to 0.10

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Tue Dec  9 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8.5-2
- make the example nsslapd-pluginpath values the same on 32- and 64-bit
  systems, because we can depend on the directory server "knowing" which
  directory to search for the plugins

* Mon Dec  8 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8.5-1
- update to 0.8.5 to suppress duplicate values for attributes in the schema
  compatibility plugin

* Thu Dec  4 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8.4-1
- update to 0.8.4 to fix:
  - problems updating references, particularly those for %%referred() (#474478)
  - inability to notice internal add/modify/modrdn/delete operations (really
    this time) (#474426)

* Wed Dec  3 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8.3-1
- update to 0.8.3 to also notice and reflect changes caused by internal
  add/modify/modrdn/delete operations
 
* Wed Nov 19 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8.2-1
- update to 0.8.2 to remove a redundant read lock in the schema-compat plugin

* Fri Nov  7 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.9-1
- update to 0.9

* Fri Oct  3 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8.1-1
- update to 0.8.1 to fix a heap corruption (Rich Megginson)

* Wed Aug  6 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.8-1
- update to 0.8

* Wed Aug  6 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.7-1
- update to 0.7

* Wed Jul 23 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.6-1
- rebuild (and make rpmlint happy)

* Wed Jul  9 2008 Nalin Dahyabhai <nalin@redhat.com> - 0.2-1
- initial package
