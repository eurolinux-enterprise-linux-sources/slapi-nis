AC_INIT(slapi-nis,0.56)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
LT_INIT([disable-static])
AM_CONDITIONAL(GCC,[test x$GCC = xyes])
AM_MAINTAINER_MODE

specversion=`awk '/^Version:/ {print $NF}' $srcdir/slapi-nis.spec | head -n1`
if test x$specversion != x$PACKAGE_VERSION ; then
	AC_MSG_ERROR([Package version skew between slapi-nis.spec and configure.ac.])
fi

AC_ARG_WITH(tcp-wrappers,
	    AS_HELP_STRING([--with-tcp-wrappers=AUTO],
			   [use tcp-wrappers]),
	    tcp_wrappers=$withval,tcp_wrappers=AUTO)
if test x$tcp_wrappers != xno ; then
	AC_CHECK_HEADERS(tcpd.h)
	if test x$ac_cv_header_tcpd_h != xyes ; then
		if test x$tcp_wrappers = xyes ; then
			AC_MSG_ERROR([tcp-wrappers enabled but tcpd.h not found])
		elif test x$tcp_wrappers != xno ; then
			AC_MSG_WARN([tcp-wrappers enabled but tcpd.h not found])
		fi
	else
		saved_LIBS="$LIBS"
		LIBS=
		AC_CHECK_FUNC(hosts_access,,AC_CHECK_LIB(wrap,hosts_access))
		LIBWRAP="$LIBS"
		LIBS="$saved_LIBS"
	fi
fi
AC_SUBST(LIBWRAP)

AC_ARG_WITH(tcp-wrappers-name,
	    AS_HELP_STRING([--with-tcp-wrappers-name=service],
			   [tcp-wrappers and network service name (nis-plugin)]),
	    tcpwrapname=$withval,tcpwrapname=nis-plugin)
AC_DEFINE_UNQUOTED(DEFAULT_TCPWRAP_NAME,"$tcpwrapname",
		   [Define to the default application name to use when evaluating hosts.allow and hosts.deny.])
AC_SUBST(tcpwrapname)

AC_ARG_WITH(domain,
	    AS_HELP_STRING([--with-domain=[[example.com]]],
			   [select a default domain name]),
	    mydomain=$withval,
	    mydomain=example.com)
mysuffix=`echo "$mydomain" | sed -e 's:^:dc=:g' -e 's:\.:, dc=:g'`

AC_ARG_WITH(server,
	    AS_HELP_STRING([--with-server=[[dirsrv]]],
			   [select a specific server implementation (dirsrv)]),
	    server=$withval,
	    server=dirsrv)

AC_ARG_WITH(ldap,
	    AS_HELP_STRING([--with-ldap=IMPL],
			   [which LDAP library to use (none|mozldap|openldap)]),
	    ldapimpl=$withval,
	    ldapimpl=none)

thread_api=NSPR
thread_lock_api=NSPR
case "$server" in
dirsrv)
	case "$ldapimpl" in
	mozldap)
		runtime_modules="mozldap nss nspr"
		LDAP_CFLAGS=
		LDAP_LIBS=
		;;
	openldap)
		runtime_modules="nss nspr"
		LDAP_CFLAGS=
		LDAP_LIBS="-lldap_r -llber"
		;;
	*)
		runtime_modules="nss nspr"
		LDAP_CFLAGS=
		LDAP_LIBS=
		;;
	esac
	PKG_CHECK_MODULES(RUNTIME,$runtime_modules)
	saved_CFLAGS="$CFLAGS"
	saved_LIBS="$LIBS"
	CFLAGS="$CFLAGS $RUNTIME_CFLAGS"
	LIBS="$LIBS $RUNTIME_LIBS"
	AC_CHECK_HEADER(dirsrv/slapi-plugin.h,
			AC_DEFINE(HAVE_DIRSRV_SLAPI_PLUGIN_H,1,
				[Define if you have <dirsrv/slapi-plugin.h>]),,[
			#include <nspr.h>
			#include <nss.h>
			])
	if test x$ac_cv_header_dirsrv_slapi_plugin_h = xno ; then
		AC_ERROR([<dirsrv/slapi-plugin.h> not found])
	fi
	dnl We don't actually care about NULL, but the last item in the
	dnl list has weird things done to its variable name.
	AC_CHECK_DECLS([slapi_new_rwlock,
			SLAPI_PLUGIN_POST_ADD_FN,
			SLAPI_PLUGIN_POST_MODIFY_FN,
			SLAPI_PLUGIN_POST_MODRDN_FN,
			SLAPI_PLUGIN_POST_DELETE_FN,
			SLAPI_PLUGIN_INTERNAL_POST_ADD_FN,
			SLAPI_PLUGIN_INTERNAL_POST_MODIFY_FN,
			SLAPI_PLUGIN_INTERNAL_POST_MODRDN_FN,
			SLAPI_PLUGIN_INTERNAL_POST_DELETE_FN,
			SLAPI_PLUGIN_BE_TXN_PRE_ADD_FN,
			SLAPI_PLUGIN_BE_TXN_PRE_MODIFY_FN,
			SLAPI_PLUGIN_BE_TXN_PRE_MODRDN_FN,
			SLAPI_PLUGIN_BE_TXN_PRE_DELETE_FN,
			SLAPI_PLUGIN_BE_TXN_POST_ADD_FN,
			SLAPI_PLUGIN_BE_TXN_POST_MODIFY_FN,
			SLAPI_PLUGIN_BE_TXN_POST_MODRDN_FN,
			SLAPI_PLUGIN_BE_TXN_POST_DELETE_FN,
			SLAPI_PLUGIN_PRE_EXTOP_FN,
			NULL]
		       ,,,
		       [AC_INCLUDES_DEFAULT
		        #include <dirsrv/slapi-plugin.h>])
	CFLAGS="$saved_CFLAGS"
	LIBS="$saved_LIBS"
	thread_api=NSPR
	if test x$ac_cv_have_decl_slapi_new_rwlock = xyes ; then
		thread_lock_api=SLAPI
	else
		thread_lock_api=POSIX
	fi
	;;
*)
	RUNTIME_CFLAGS=
	RUNTIME_LIBS=
	LDAP_CFLAGS=
	LDAP_LIBS="-lldap -lber"
	AC_CHECK_HEADERS(slapi-plugin.h)
	if test x$ac_cv_header_slapi_plugin_h = xno ; then
		AC_ERROR([<slapi-plugin.h> not found])
	fi
	thread_api=POSIX
	thread_lock_api=POSIX
	saved_LIBS="$LIBS"
	LIBS=
	AC_CHECK_FUNC(pthread_create,,AC_CHECK_LIB(pthread,pthread_create))
	LIBPTHREAD="$LIBS"
	LIBS="$saved_LIBS"
	;;
esac

AC_ARG_ENABLE(be-txns,
	AS_HELP_STRING([--disable-be-txns],
		       [build without support for backend transactions]),
	if test x$enableval = xno ; then
		transactions=false
	elif test x$enableval = xyes; then
		transactions=true
	fi,
	transactions=auto)
if test x$transactions = xauto ; then
	AC_MSG_CHECKING([for transaction support])
	transactions=false
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_PRE_ADD_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_PRE_MODIFY_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_PRE_MODRDN_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_PRE_DELETE_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_POST_ADD_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_POST_MODIFY_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_POST_MODRDN_FN = xyes; then
	if test x$ac_cv_have_decl_SLAPI_PLUGIN_BE_TXN_POST_DELETE_FN = xyes; then
		transactions=true
	fi
	fi
	fi
	fi
	fi
	fi
	fi
	fi
	if $transactions ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi
else
	if $transactions ; then
		AC_MSG_RESULT([enabling backend transaction support])
	else
		AC_MSG_RESULT([disabling backend transaction support])
	fi
fi
if $transactions ; then
	AC_DEFINE(SLAPI_NIS_SUPPORT_BE_TXNS,1,
		  [Define if support for backend transactions should be built.])
fi

AC_ARG_ENABLE(be-txns-by-default,
	AS_HELP_STRING([--disable-be-txns-by-default],
		       [disable use of backend transactions by default]),
	if test x$enableval = xno ; then
		deftransactions=0
	elif test x$enableval = xyes ; then
		if ! $transactions ; then
			AC_MSG_ERROR([unable to enable transactions by default without support for them])
		fi
		deftransactions=1
	else
		deftransactions=auto
	fi,
	deftransactions=auto)
if test $deftransactions = auto ; then
	AC_MSG_CHECKING([whether or not to enable transaction support by default])
	if $transactions ; then
		AC_MSG_RESULT([yes])
		deftransactions=1
	else
		AC_MSG_RESULT([no transaction support, so no])
		deftransactions=0
	fi
elif test x$deftransactions = x0 ; then
	AC_MSG_RESULT([disabling backend transactions by default])
elif test x$deftransactions = x1 ; then
	AC_MSG_RESULT([enabling backend transactions by default])
fi
AC_DEFINE_UNQUOTED(DEFAULT_PLUGIN_USE_BETXNS,$deftransactions,
		   [Define non-zero if support for backend transactions should be enabled by default.])

AH_VERBATIM([ZZ_PACKAGE_VERSION_HAVE_TXNS],
[
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
#ifdef DEFAULT_PLUGIN_USE_BETXNS
#define PACKAGE_VERSION_TXNS " (betxn support available and enabled by default)"
#else
#define PACKAGE_VERSION_TXNS " (betxn support available but not enabled by default)"
#endif
#else
#define PACKAGE_VERSION_TXNS " (betxn support not available)"
#endif
])

if test $thread_api = NSPR ; then
	AC_DEFINE(USE_NSPR_THREADS,1,[Define to use NSPR threading functions.])
elif test $thread_api = POSIX ; then
	AC_DEFINE(USE_PTHREADS,1,[Define to use POSIX threading functions.])
else
	AC_MSG_ERROR([no threading API selected])
fi

if test $thread_lock_api = SLAPI ; then
	AC_DEFINE(USE_SLAPI_LOCKS,1,[Define to use SLAPI read/write locks.])
elif test $thread_lock_api = NSPR ; then
	AC_DEFINE(USE_NSPR_LOCKS,1,[Define to use NSPR read/write locks.])
elif test $thread_lock_api = POSIX ; then
	AC_DEFINE(USE_PTHREAD_LOCKS,1,[Define to use POSIX read/write locks.])
else
	AC_MSG_ERROR([no locking API selected])
fi

AC_SUBST(RUNTIME_CFLAGS)
AC_SUBST(RUNTIME_LIBS)
AC_SUBST(LDAP_CFLAGS)
AC_SUBST(LDAP_LIBS)
AC_SUBST(LIBPTHREAD)

AC_ARG_WITH(tirpc,
	    AS_HELP_STRING([--with-tirpc], [use libtirpc]),
	    use_tirpc=$withval,
	    [
	    AC_CHECK_HEADERS(rpc/xdr.h)
	    if test x$ac_cv_header_rpc_xdr_h = xno ; then
		    use_tirpc=yes
	    else
		    use_tirpc=no
	    fi
	    ])
if test $use_tirpc = yes ; then
	PKG_CHECK_MODULES(TIRPC,libtirpc)
else
	RPC_CFLAGS=
	RPC_LIBS=-lnsl
fi
AC_SUBST(RPC_CFLAGS)
AC_SUBST(RPC_LIBS)

savedlibs="$LIBS"
LIBS="$LIBS $TIRPC_LIBS $RPC_LIBS"
AC_CHECK_FUNCS(clnttcp6_create)
LIBS="$savedlibs"

if false ; then
AC_ARG_WITH(asyncns,
	    AS_HELP_STRING([--with-asyncns=AUTO], [use libasyncns to back-end hosts maps]),
	    use_asyncns=$withval,
	    use_asyncns=AUTO)
if pkg-config libasyncns 2> /dev/null ; then
	if test $use_asyncns != no ; then
		AC_DEFINE(HAVE_LIBASYNCNS,1,[Define if you have libasyncns.])
		PKG_CHECK_MODULES(ASYNCNS,libasyncns)
	else
		ASYNCNS_CFLAGS=
		ASYNCNS_LIBS=
	fi
else
	if test $use_asyncns = yes ; then
		PKG_CHECK_MODULES(ASYNCNS,libasyncns)
	else
		ASYNCNS_CFLAGS=
		ASYNCNS_LIBS=
	fi
fi
AC_SUBST(ASYNCNS_CFLAGS)
AC_SUBST(ASYNCNS_LIBS)
fi

AC_ARG_WITH(nsswitch,
	    AS_HELP_STRING([--with-nsswitch],
			   [use nsswitch API to look up users and groups not found in the LDAP]),
	    use_nsswitch=$withval,use_nsswitch=AUTO)

AM_CONDITIONAL([USE_NSSWITCH], [test "x$use_nsswitch" != xno])

AC_ARG_WITH(sss_nss_idmap,
	    AS_HELP_STRING([--with-sss-nss-idmap], [use libsss_nss_idmap to discover SIDs. Requires --with-nsswitch as well]),
	    use_sss_nss_idmap=$withval,use_sss_nss_idmap=AUTO)
AC_ARG_WITH(pam,
	    AS_HELP_STRING([--with-pam],
			   [use PAM API to authenticate users not found in the LDAP. Requires --with-nsswitch as well]),
	    use_pam=$withval,use_pam=AUTO)
AC_ARG_WITH(pam-service,
	    AS_HELP_STRING([--with-pam-service=[[system-auth]]],
			   [select a PAM service name]),
	    pamservice=$withval,
	    pamservice=system-auth)
AC_DEFINE_UNQUOTED(DEFAULT_PAM_SERVICE,"$pamservice",
		   [Define to name of the PAM service used when authenticating server-side users (system-auth).])

if test "x$use_nsswitch" = xno ; then
	if test "x$use_pam" = xyes ; then
		AC_ERROR([Cannot use PAM without nsswitch enabled])
	else
		if test "x$use_pam" = xAUTO ; then
			use_pam=no
		fi
	fi
fi
AM_CONDITIONAL([USE_PAM], [test "x$use_pam" != xno])

if test "x$use_nsswitch" != xno ; then
	AC_CHECK_HEADERS([stdint.h nss.h dlfcn.h])
	if pkg-config sss_nss_idmap 2> /dev/null ; then
		if test x$use_sss_nss_idmap != xno ; then
			AC_DEFINE(HAVE_SSS_NSS_IDMAP,1,[Define if you have libsss_nss_idmap.])
			PKG_CHECK_MODULES(SSS_NSS_IDMAP,sss_nss_idmap)
		else
			SSS_NSS_IDMAP_CFLAGS=
			SSS_NSS_IDMAP_LIBS=
		fi
	else
		if test x$use_sss_nss_idmap = xyes ; then
			PKG_CHECK_MODULES(SSS_NSS_IDMAP,sss_nss_idmap)
		else
			SSS_NSS_IDMAP_CFLAGS=
			SSS_NSS_IDMAP_LIBS=
		fi
	fi
	AC_SUBST(SSS_NSS_IDMAP_CFLAGS)
	AC_SUBST(SSS_NSS_IDMAP_LIBS)

	if test "x$use_pam" != xno ; then
		AC_CHECK_HEADERS(security/pam_appl.h)
		if test x$ac_cv_header_security_pam_appl_h = xyes ; then
			use_pam=yes
		else
			use_pam=no
		fi

		if test $use_pam = yes ; then
			PAM_CFLAGS=
			PAM_LIBS=-lpam
			AC_DEFINE(USE_PAM,1,[Use PAM API to authenticate users not found in the LDAP tree])
		else
			AC_ERROR([<security/pam_appl.h> not found and it is required for nsswitch-based mode])
		fi
		AC_SUBST(PAM_CFLAGS)
		AC_SUBST(PAM_LIBS)
	fi
	AC_DEFINE(USE_NSSWITCH,1,[Use nsswitch API to lookup users and groups not found in the LDAP tree])
fi

use_idviews=true
AC_ARG_WITH(idviews,
	    AS_HELP_STRING([--with-idviews], [Use FreeIPA ID views to override POSIX IDs of users and groups]),
	    use_idviews=$withval,use_idviews=yes)
if test "x$use_idviews" = xyes ; then
	AC_MSG_RESULT([FreeIPA ID views support is enabled])
	AC_DEFINE(USE_IPA_IDVIEWS,1,[Use FreeIPA ID views to override POSIX attributes of users and groups per view.])
	AC_DEFINE(IPA_IDVIEWS_ATTR_ANCHORUUID, ["ipaAnchorUUID"],[FreeIPA attr unique pointer for id overrides])
	AC_DEFINE(IPA_IDVIEWS_ATTR_ORIGINALUID, ["ipaOriginalUid"],[FreeIPA attr original uid value for user id overrides])
else
	AC_MSG_RESULT([FreeIPA ID views support is disabled])
fi
AM_CONDITIONAL([USE_IPA_IDVIEWS], [test "x$use_idviews" != xno])

mylibdir=`eval echo "$libdir" | sed "s,NONE,${ac_default_prefix},g"`
mylibdir=`eval echo "$mylibdir" | sed "s,NONE,${ac_prefix},g"`
case "$server" in
dirsrv)
	myplugindir="$mylibdir/dirsrv/plugins"
	;;
openldap)
	myplugindir="$mylibdir/openldap"
	;;
*)
	myplugindir="$mylibdir/$PACKAGE"
	;;
esac

AC_SUBST(myplugindir)
AC_SUBST(mydomain)
AC_SUBST(mysuffix)

myincludedir=`eval echo "$includedir" | sed "s,NONE,${ac_default_prefix},g"`
myincludedir=`eval echo "$myincludedir" | sed "s,NONE,${ac_prefix},g"`

AC_ARG_WITH(users,
	    AS_HELP_STRING([--with-users=cn=Users],
			   [select a specific user entry container (cn=Users)]),
	    people=$withval,
	    people=[cn=Users])
AC_SUBST(people)
AC_ARG_WITH(groups,
	    AS_HELP_STRING([--with-groups=cn=Groups],
			   [select a specific group entry container (cn=Groups)]),
	    groups=$withval,
	    groups=[cn=Groups])
AC_SUBST(groups)

AC_DEFINE(DEFAULT_MAX_DGRAM_SIZE,YPMAXRECORD,[Define to the default maximum datagram reply size.])
AC_DEFINE(DEFAULT_MAX_VALUE_SIZE,(256 * 1024),[Define to the default maximum map entry key and value size.])
AC_DEFINE(DEFAULT_TARGET_REPLY_SIZE,(4 * 1024),[Define to the default target size for a connected reply fragment.])
AC_DEFINE_UNQUOTED(DEFAULT_IGNORE_SUBTREE,["cn=tasks,cn=config"],[Define to the default subtree to ignore if no value is explicitly configured for the map.])

AM_CONDITIONAL(NIS,true)
nisbaseattr=nis-base
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_BASE_ATTR,"$nisbaseattr",
		   [Define to name of the attribute which lists the containers for entries for a given map.])
nisrestrictsubtreeattr=nis-restrict-subtree
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_RESTRICT_SUBTREES_ATTR,"$nisrestrictsubtreeattr",
		   [Define to name of the attribute which lists the only subtrees which we care about when locating entries and reading data to be used for constructing entries for a given container.])
nisignoresubtreeattr=nis-ignore-subtree
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_IGNORE_SUBTREES_ATTR,"$nisignoresubtreeattr",
		   [Define to name of the attribute which lists the subtrees to ignore when locating entries and reading data to be used for constructing entries for a given container.])
nisfilterattr=nis-filter
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_FILTER_ATTR,"$nisfilterattr",
		   [Define to name of the attribute which holds the filter for selecting entries for a given map.])
niskeyformatattr=nis-key-format
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_KEY_ATTR,"$niskeyformatattr",
		   [Define to name of the map configuration attribute which holds the format specifier for single keys for a map entry.])
niskeysformatattr=nis-keys-format
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_KEYS_ATTR,"$niskeysformatattr",
		   [Define to name of the map configuration attribute which holds the format specifier for possibly-multiple keys for a map entry.])
nisvalueformatattr=nis-value-format
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_VALUE_ATTR,"$nisvalueformatattr",
		   [Define to name of the map configuration attribute which holds the format specifier for the value for a map entry.])
nisvaluesformatattr=nis-values-format
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_VALUES_ATTR,"$nisvaluesformatattr",
		   [Define to name of the map configuration attribute which holds the format specifier for the possibly-multiple values for a map entry.])
domainattr=nis-domain
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_DOMAIN_ATTR,"$domainattr",
		   [Define to name of the map configuration attribute which holds the name of the domain of the map.])
mapattr=nis-map
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_MAP_ATTR,"$mapattr",
		   [Define to name of the map configuration attribute which holds the name of the map.])
disallowedcharsattr=nis-disallowed-chars
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_DISALLOWED_CHARS_ATTR,"$disallowedcharsattr",
		   [Define to the list of characters which should not be allowed in attribute values which are being considered.])
secureattr=nis-secure
AC_DEFINE_UNQUOTED(NIS_MAP_CONFIGURATION_SECURE_ATTR,"$secureattr",
		   [Define to name of the map configuration attribute which determines whether or not the map is treated a 'secure' map.])

AM_CONDITIONAL(SCHEMA,true)
groupattr=schema-compat-container-group
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_GROUP_ATTR,"$groupattr",
		   [Define to name of the attribute which holds the name of the top-level container used for this set of compatibility containers.])
containerattr=schema-compat-container-rdn
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_CONTAINER_ATTR,"$containerattr",
		   [Define to name of the attribute which holds the compatibility container's RDN.])
checkaciattr=schema-compat-check-access
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_ACCESS_ATTR,"$checkaciattr",
		   [Define to name of the attribute which dictates whether or not access control is checked for this container and its contents.])
schbaseattr=schema-compat-search-base
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_BASE_ATTR,"$schbaseattr",
		   [Define to name of the attribute which lists the containers to search when locating entries to be used for constructing entries for a given container.])
schrestrictsubtreeattr=schema-compat-restrict-subtree
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_RESTRICT_SUBTREES_ATTR,"$schrestrictsubtreeattr",
		   [Define to name of the attribute which lists the only subtrees which we care about when locating entries and reading data to be used for constructing entries for a given container.])
schignoresubtreeattr=schema-compat-ignore-subtree
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_IGNORE_SUBTREES_ATTR,"$schignoresubtreeattr",
		   [Define to name of the attribute which lists the subtrees to ignore when locating entries and reading data to be used for constructing entries for a given container.])
schfilterattr=schema-compat-search-filter
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_FILTER_ATTR,"$schfilterattr",
		   [Define to name of the attribute which holds the filter for selecting entries to be used for constructing entries for a given container.])
rdnattr=schema-compat-entry-rdn
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_RDN_ATTR,"$rdnattr",
		   [Define to name of the attribute which is used to specify the RDN of a constructed entry.])
attrattr=schema-compat-entry-attribute
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_ATTR_ATTR,"$attrattr",
		   [Define to name of the attribute which is used to specify attributes to be used when constructing entries.])
nsswitchattr=schema-compat-lookup-nsswitch
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_NSSWITCH_ATTR,"$nsswitchattr",
		   [Define to name of the attribute to cause the tree to talk to nsswitch API for users and groups when they were not found in the LDAP. The value of the attribute is either 'user' or 'group'.])
nsswitchminidattr=schema-compat-nsswitch-min-id
AC_DEFINE_UNQUOTED(SCH_CONTAINER_CONFIGURATION_NSSWITCH_MIN_ID_ATTR,"$nsswitchminidattr",
		   [Define to name of the attribute which is used to define lower bound of IDs (uid or gid) looked up through nsswitch API. Everything below is not considered belonging to trusted domains.])

maxvalue_attr=nis-max-value-size
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONFIGURATION_MAXVALUE_ATTR,"$maxvalue_attr",
		   [Define to the name of the plugin configuration attribute which holds the maximum size for a NIS entry value.])
maxdgram_attr=nis-max-dgram-size
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONFIGURATION_MAXDGRAM_ATTR,"$maxdgram_attr",
		   [Define to the name of the plugin configuration attribute which holds the maximum size for a NIS datagram response.])
securenet_attr=nis-securenet
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONFIGURATION_SECURENET_ATTR,"$securenet_attr",
		   [Define to the name of the plugin configuration attribute which holds a securenets entry.])
tcpwrapname_attr=nis-tcp-wrappers-name
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONFIGURATION_TCPWRAPNAME_ATTR,"$tcpwrapname_attr",
		   [Define to the name of the plugin configuration attribute which holds service name that will be used when evaluating hosts.allow and hosts.deny.])
port_attr=nsslapd-pluginarg0
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONFIGURATION_PORT_ATTR,"$port_attr",
		   [Define to the name of the plugin configuration attribute which holds the port which the server should use by default.  If none is specified, the server will attempt to use any available port.])
ypserver_attr=nis-server
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONFIGURATION_SERVER_ATTR,"$ypserver_attr",
		   [Define to the name of the entry attribute which holds the name of a yp server which should replicate the contents of this server.])
AC_SUBST(domainattr)
AC_SUBST(mapattr)
AC_SUBST(nisbaseattr)
AC_SUBST(nisfilterattr)
AC_SUBST(niskeyformatattr)
AC_SUBST(nisvalueformatattr)
AC_SUBST(maxvalue_attr)
AC_SUBST(maxdgram_attr)
AC_SUBST(securenet_attr)
AC_SUBST(tcpwrapname)
AC_SUBST(port_attr)
AC_SUBST(schbaseattr)
AC_SUBST(schfilterattr)
AC_SUBST(schentryformatattr)
AC_SUBST(groupattr)
AC_SUBST(containerattr)

AC_PATH_PROG(RPCGEN,[rpcgen],no-rpcgen,[$PATH$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/usr/libexec])
if test x$RPCGEN = xno-rpcgen ; then
	AC_MSG_ERROR([rpcgen needed but not found])
fi

if test "$server" = dirsrv ; then
	AC_PATH_PROG(SLAPD,[ns-slapd],no-slapd,[$PATH$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR/usr/libexec])
fi

AM_CONDITIONAL(CAN_TEST,[test "$server" = dirsrv && test "$SLAPD" != no-slapd])
AC_SUBST(CAN_TEST)
test_user=`id -un`
AC_SUBST(test_user)
test_uid=`id -u`
AC_SUBST(test_uid)
test_group=`id -gn`
AC_SUBST(test_group)
test_gid=`id -g`
AC_SUBST(test_gid)
test_basedn=dc=example,dc=com
AC_SUBST(test_basedn)
while true ; do
	test_ldapport=$RANDOM
	if test $test_ldapport -ge 1024 ; then
		break
	fi
done
AC_SUBST(test_ldapport)
while true ; do
	test_nisport=$RANDOM
	if test $test_nisport -ge 1024 ; then
		break
	fi
done
AC_SUBST(test_nisport)
NIS_PLUGIN_CONTINUE_WITHOUT_PORTMAP_ENV="nis_plugin_continue_without_portmap_for_testing_only_no_i_really_mean_that"
AC_DEFINE_UNQUOTED(NIS_PLUGIN_CONTINUE_WITHOUT_PORTMAP_ENV,"$NIS_PLUGIN_CONTINUE_WITHOUT_PORTMAP_ENV",[Define to the environment variable which will override the fail-if-unable-to-use-the-portmapper logic.])
AC_SUBST(NIS_PLUGIN_CONTINUE_WITHOUT_PORTMAP_ENV)
NIS_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV="nis_plugin_process_uninteresting_updates_for_testing_only_no_i_really_mean_that"
AC_DEFINE_UNQUOTED(NIS_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV,"$NIS_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV",[Define to the environment variable which will override the default skip-uninteresting-updates logic for the NIS plugin.])
AC_SUBST(NIS_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV)
SCHEMA_COMPAT_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV="schema_compat_plugin_process_uninteresting_updates_for_testing_only_no_i_really_mean_that"
AC_DEFINE_UNQUOTED(SCHEMA_COMPAT_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV,"$SCHEMA_COMPAT_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV",[Define to the environment variable which will override the default skip-uninteresting-updates logic for the schema compat plugin.])
AC_SUBST(SCHEMA_COMPAT_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV)
AC_SUBST(TRACE_CMD)

CONFIGURED_LINK_FLAGS=
AC_ARG_ENABLE(unloading,
	      AS_HELP_STRING([--disable-unloading],
			     [attempt to mark the plugins as not-to-be-unloaded]),
	      if test x$enableval = xno ; then
		  AC_MSG_RESULT([marking plugins as not-to-be-unloaded])
		  [CONFIGURED_LINK_FLAGS='-Wl,-z,nodelete']
	      else
	          AC_MSG_RESULT([leaving plugins as okay-to-unload])
	      fi,
	      AC_MSG_RESULT([leaving plugins as okay-to-unload]))
AC_SUBST(CONFIGURED_LINK_FLAGS)

TESTS_USE_REFINT=true
TESTS_USE_MEMBEROF=true
TESTS_USE_MANAGED_ENTRIES=true
TESTS_USE_USN=true
TESTS_USE_BETXN=true
AC_ARG_ENABLE(tests-with-refint,
	      AS_HELP_STRING([--disable-tests-with-refint],
			     [skip tests which use the the refint plugin]),
	      if test x$enableval = xyes ; then
		  AC_MSG_RESULT([running tests with referential integrity enabled])
	      else
	          AC_MSG_RESULT([running tests with referential integrity disabled])
		  TESTS_USE_REFINT=false
	      fi,
	      AC_MSG_RESULT([running tests with referential integrity enabled]))
AC_ARG_ENABLE(tests-with-memberof,
	      AS_HELP_STRING([--disable-tests-with-memberof],
			     [skip tests which are impacted by the memberof plugin]),
	      if test x$enableval = xyes ; then
		  AC_MSG_RESULT([running tests with memberof enabled])
	      else
	          AC_MSG_RESULT([running tests with memberof disabled])
		  TESTS_USE_MEMBEROF=false
	      fi,
	      AC_MSG_RESULT([running tests with memberof enabled]))
AC_ARG_ENABLE(tests-with-managed-entries,
	      AS_HELP_STRING([--disable-tests-with-managed-entries],
			     [skip tests which are impacted by the managed entries plugin]),
	      if test x$enableval = xyes ; then
		  AC_MSG_RESULT([running tests with managed entries enabled])
	      else
	          AC_MSG_RESULT([running tests with managed entries disabled])
		  TESTS_USE_MANAGED_ENTRIES=false
	      fi,
	      AC_MSG_RESULT([running tests with managed entries enabled]))
AC_ARG_ENABLE(tests-with-usn,
	      AS_HELP_STRING([--disable-tests-with-usn],
			     [skip tests which are impacted by the usn plugin]),
	      if test x$enableval = xyes ; then
		  AC_MSG_RESULT([running tests with usn enabled])
	      else
	          AC_MSG_RESULT([running tests with usn disabled])
		  TESTS_USE_USN=false
	      fi,
	      AC_MSG_RESULT([running tests with usn enabled]))
AC_ARG_ENABLE(tests-with-betxn,
	      AS_HELP_STRING([--disable-tests-with-betxn],
			     [skip tests which are impacted by betxns]),
	      if test x$enableval = xyes ; then
		  AC_MSG_RESULT([running tests with betxn enabled])
	      else
	          AC_MSG_RESULT([running tests with betxn disabled])
		  TESTS_USE_BETXN=false
	      fi,
	      AC_MSG_RESULT([running tests with betxn enabled]))
AC_SUBST(TESTS_USE_REFINT)
AC_SUBST(TESTS_USE_MEMBEROF)
AC_SUBST(TESTS_USE_MANAGED_ENTRIES)
AC_SUBST(TESTS_USE_USN)
AC_SUBST(TESTS_USE_BETXN)
if $TESTS_USE_BETXN ; then
	TEST_PLUGIN_BETXN_ENABLE_OR_NOT="nsslapd-pluginbetxn: on"
else
	TEST_PLUGIN_BETXN_ENABLE_OR_NOT="nsslapd-pluginbetxn: off"
fi
AC_SUBST(TEST_PLUGIN_BETXN_ENABLE_OR_NOT)

AC_CONFIG_HEADER(src/config.h)
AC_OUTPUT(Makefile yp/Makefile src/Makefile
	  doc/examples/nis-plugin-example.ldif doc/examples/sch-plugin-example.ldif
	  tests/Makefile tests/clients/Makefile
	  tests/slapd.sh tests/config/dse.ldif.initial
	  tests/config/dse.ldif.refint
	  tests/config/dse.ldif.memberof
	  tests/config/dse.ldif.mep
	  tests/config/dse.ldif.usn
	  src/nisserver-plugin-defs.1
	  tests/test36-schema-nsswitch/wrap_passwd)
