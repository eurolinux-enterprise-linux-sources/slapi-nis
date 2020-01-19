#!/bin/sh
#
#  A simplistic migration script, useful for pulling data from a production
#  NIS domain and transforming it into LDIF for import into an IPA server.
#
domain=`domainname`
server=`ypwhich -d $domain 2> /dev/null`
suffix=dc=example,dc=com
people=cn=Users
groups=cn=Group
ipa=false
realm=`echo "$domain" | tr '[a-z]' '[A-Z]'`
rfc2307bis=false
mergegroups=true
maps=
automap=false
help=false
email=false
containers=false
entries=true
files=false
minuid=-1
mingid=-1

object_from_attr()
{
	case "$1" in
	cn)
		containerobject=nsContainer
		;;
	dc)
		containerobject=domain
		;;
	ou)
		containerobject=organizationalUnit
		;;
	*)
		containerobject=extensibleObject
		;;
	esac
	echo $containerobject
}

migrate_passwd() {
	if $containers ; then
		nameattr=`echo "$people" | cut -f1 -d=`
		nameval=`echo "$people" | cut -f2- -d=`
		containerclass=`object_from_attr "$nameattr"`
		grep -v '^$' <<- EOF
		dn: $people,$suffix
		${nameattr}: ${nameval}
		objectClass: $containerclass
		EOF
		echo
	fi
	while read key value ; do
		if ! $entries ; then
			continue
		fi
		uid=`echo "$value" | cut -d: -f1`
		userpassword=`echo "$value" | cut -d: -f2`
		case "$userpassword" in
		'*'*|'!'*) userpassword= ;;
		*);;
		esac
		uidnumber=`echo "$value" | cut -d: -f3`
		gidnumber=`echo "$value" | cut -d: -f4`
		gecos=`echo "$value" | cut -d: -f5`
		homedirectory=`echo "$value" | cut -d: -f6`
		loginshell=`echo "$value" | cut -d: -f7`
		cn=`echo "$gecos" | cut -d, -f1`
		givenname=`echo "$gecos" | awk '{print $1}'`
		sn=`echo "$gecos" | awk '{print $NF}'`
		if test "$uidnumber" -lt "$minuid" ; then
			continue
		fi
		grep -v '^$' <<- EOF
			dn: uid=$uid,$people,$suffix
			objectClass: posixAccount
			uid: $uid
			uidNumber: $uidnumber
			gidNumber: $gidnumber
			homeDirectory: $homedirectory
			${userpassword:+userPassword: "{CRYPT}"$userpassword}
			${loginshell:+loginShell: $loginshell}
		EOF
		if $rfc2307bis || $ipa || $email ; then
			grep -v '^$' <<- EOF
			objectClass: inetOrgPerson
			objectClass: inetUser
			objectClass: organizationalPerson
			objectClass: person
			cn: ${cn:-$uid}
			sn: ${sn:-$uid}
			givenName: ${givenname:-$uid}
			mail: ${uid}@${domain}
			EOF
		fi
		if $ipa ; then
			grep -v '^$' <<- EOF
				objectClass: krbprincipalaux
				objectClass: krbticketpolicyaux
				krbPrincipalName: $uid@$realm
				krbTicketFlags: 640
				krbLastPwdChange: 19700101000000Z
				krbPasswordExpiration: 19700101000000Z
			EOF
		fi
		echo
	done
}

migrate_group() {
	if $containers ; then
		nameattr=`echo "$groups" | cut -f1 -d=`
		nameval=`echo "$groups" | cut -f2- -d=`
		containerclass=`object_from_attr "$nameattr"`
		grep -v '^$' <<- EOF
		dn: $groups,$suffix
		${nameattr}: ${nameval}
		objectClass: $containerclass
		EOF
		echo
	fi
	while read key value ; do
		if ! $entries ; then
			continue
		fi
		gid=`echo "$value" | cut -d: -f1`
		userpassword=`echo "$value" | cut -d: -f2`
		gidnumber=`echo "$value" | cut -d: -f3`
		members=`echo "$value" | cut -d: -f4`
		if test "$gidnumber" -lt "$mingid" ; then
			continue
		fi
		grep -v '^$' <<- EOF
			dn: cn=$gid,$groups,$suffix
			objectClass: posixGroup
			cn: $gid
			gidNumber: $gidnumber
			${userpassword:+userPassword: "{CRYPT}"$userpassword}
		EOF
		if $rfc2307bis || $ipa ; then
			grep -v '^$' <<- EOF
				objectClass: groupOfNames
			EOF
			for member in `echo "$members" | sed 's:,: :g'` ; do
				echo member: uid=$member,$people,$suffix
			done
		else
			for member in `echo "$members" | sed 's:,: :g'` ; do
				echo memberUid: $member
			done
		fi
		echo
	done
}

migrate_automount() {
	if $containers ; then
		grep -v '^$' <<- EOF
			dn: automountMapName=$1,$suffix
			objectClass: automountMap
			automountMapName: $1
		EOF
		echo
	fi
	while read key value ; do
		if ! $entries ; then
			continue
		fi
		grep -v '^$' <<- EOF
			dn: automountKey=$key,automountMap=$1,$suffix
			objectClass: automount
			automountKey: $key
			automountInformation: $value
		EOF
		echo
	done
}

migrate_nis() {
	if $containers ; then
		grep -v '^$' <<- EOF
			dn: nisMapName=$1,$suffix
			objectClass: nisMap
			automountMapName: $1
		EOF
		echo
	fi
	while read key value ; do
		if ! $entries ; then
			continue
		fi
		grep -v '^$' <<- EOF
			dn: cn=$key,automountMap=$1,$suffix
			objectClass: nisObject
			nisMapName: $1
			cn: $key
			nisEntry: $value
		EOF
		echo
	done
}

mergegroups() {
	if $mergegroups ; then
		awk -F: '
		BEGIN { OFS=":" }
		{ 
			if ((length(NAMES[$3]) == 0) ||
			    (length(NAMES[$3]) > length($1))) {
				NAMES[$3] = $1
			}
			GIDS[$3] = $3
			PASS[$3] = $2
			if (length(MEMBERS[$3]) > 0) {
				MEMBERS[$3] = MEMBERS[$3] "," $4
			} else {
				MEMBERS[$3] = $4
			}
		}
		END {
			for (GID in GIDS) {
				print NAMES[GID],PASS[GID],GID,MEMBERS[GID]
			}
		}'
	else
		cat
	fi
}

get_map() {
	case "$1" in
	passwd*)
		if $files ; then
			awk -F: '{print $1,$0}' /etc/passwd | sort
		else
			ypcat -k ${server:+-h $server} ${domain:+-d $domain} passwd.byname | sort
		fi
		;;
	group*)
		if $files ; then
			awk -F: '{print $1,$0}' /etc/group | mergegroups | sort
		else
			ypcat -k ${server:+-h $server} ${domain:+-d $domain} group.byname | mergegroups | sort
		fi
		;;
	*)
		if $files ; then
			awk '{print $1,$0}' /etc/"$1"
		else
			ypcat -k ${server:+-h $server} ${domain:+-d $domain} "$1" | sort
		fi
		;;
	esac
}

migrate_map() {
	case "$1" in
	passwd*)
		(get_map "$1" || echo) | migrate_passwd
		;;
	group*)
		(get_map "$1" || echo) | migrate_group
		;;
	auto.*|auto_*)
		(get_map "$1" || echo) | migrate_automount "$1"
		;;
	*)
		(get_map "$1" || echo) | migrate_nis "$1"
		;;
	esac
}

while test $# -gt 0 ; do
	case "$1" in
	--domain=*)
		domain=`echo "$1" | cut -f2- -d=`
		automap=false
		;;
	--domain)
		shift
		domain="$1"
		automap=false
		;;
	--server=*)
		server=`echo "$1" | cut -f2- -d=`
		automap=false
		;;
	--server)
		shift
		server="$1"
		automap=false
		;;
	--suffix=*)
		suffix=`echo "$1" | cut -f2- -d=`
		;;
	--suffix)
		shift
		suffix="$1"
		;;
	--people=*)
		people=`echo "$1" | cut -f2- -d=`
		;;
	--people)
		shift
		people="$1"
		;;
	--groups=*)
		groups=`echo "$1" | cut -f2- -d=`
		;;
	--groups)
		shift
		groups="$1"
		;;
	--nomergegroups)
		mergegroups=false
		;;
	--rfc2307bis)
		rfc2307bis=true
		;;
	--ipa)
		ipa=true
		;;
	--email)
		email=true
		;;
	--realm=*)
		realm=`echo "$1" | cut -f2- -d= | tr '[a-z]' '[A-Z]'`
		automap=false
		;;
	--realm)
		shift
		realm=`echo "$1"                | tr '[a-z]' '[A-Z]'`
		automap=false
		;;
	-a|--all)
		automap=true
		;;
	--files)
		files=true
		;;
	--containers)
		containers=true
		;;
	--just-containers)
		containers=true
		entries=false
		;;
	-*|-h|--help)
		help=true
		;;
	*)
		maps="${maps:+$maps }$1"
		;;
	esac
	shift
done

if $automap && test -z "$maps" ; then
	maps=`./ypmaplist.py`
fi
if $help || test -z "$maps" ; then
	echo `basename $0`: create LDIF from NIS maps
	echo Usage: `basename $0` "[options] [mapname [...]]"
	cat <<- EOF
	Options:
	-h --help		Print this text.
	--domain		Query maps for a non-default domain (default is
	 			"$domain").
	--server		Query a non-default server (default is
	 			"$server").
	--files			Read local files in /etc instead of NIS maps.
	--suffix		Store entries under a non-default suffix (default is
	 			"$suffix").
	--people		Store account entries under a non-default container
	 			under the suffix (default is "$people").
	--groups		Store group entries under a non-default container
	 			under the suffix (default is "$groups").
	--nomergegroups		Don't merge group entries which have the same GID.
	--rfc2307bis		Use groupOfNames groups, create user account
	 			entries which are also inetOrgPerson entries.
	--ipa			Use groupOfNames groups, create user account
	 			entries which are also inetOrgPerson and Kerberos
	 			user entries.
	--realm			Use a non-default Kerberos realm name (default is
	 			"$realm").
	--email			Add email addresses by default (default domain for
	 			mail addresses is "$domain").
	-a --all		Attempt to migrate all maps in the local domain.
	 			(Can not be used with either the --server or
	 			the --domain options.)
	--containers		Create containers for maps in addition to entries.
	--just-containers	Create containers for maps, but not for entries.
	EOF
else
	seen_passwd=false
	seen_group=false
	for map in $maps ; do
		seen_before=false
		case "$map" in
		*.by*)
			base=`echo "$map" | sed 's,\.by.*,,g'`
			case $base in
			passwd)
				if $seen_passwd ; then
					seen_before=true
				fi
				seen_passwd=true
				;;
			group)
				if $seen_group ; then
					seen_before=true
				fi
				seen_group=true
				;;
			esac
			;;
		esac
		$seen_before || migrate_map "$map"
	done
fi
