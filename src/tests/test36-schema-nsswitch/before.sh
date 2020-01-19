#!/bin/sh
testuser1="testuser1:**:1234:2345:Test User 1:/home/testuser1:/bin/sh"
testuser2="testuser2:***:12345:23456:Test User 2:/home/testuser2:/bin/sh"
testuser3="testuser3, for real:***:123456:234567:Test User 3:/home/testuser2:/bin/sh"
testgroup1="testgroup1:****:3456:testuser1,testuser2"
testgroup2="testgroup2:*****:34567:testuser1,testuser2"
testgroup3="testgroup3, for real:*****:345678:testuser1,testuser2"

searches() {
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixaccount)(uid=testuser1))" \
		dn uid userpassword uidnumber gidnumber gecos loginshell homedirectory |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixaccount)(uidnumber=1234))" \
		dn uid userpassword uidnumber gidnumber gecos loginshell homedirectory |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixaccount)(uid=testuser2))" \
		dn uid userpassword uidnumber gidnumber gecos loginshell homedirectory |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixaccount)(uidnumber=12345))" \
		dn uid userpassword uidnumber gidnumber gecos loginshell homedirectory |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixaccount)(uid=testuser3, for real))" \
		dn uid userpassword uidnumber gidnumber gecos loginshell homedirectory |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixaccount)(uidnumber=123456))" \
		dn uid userpassword uidnumber gidnumber gecos loginshell homedirectory |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixgroup)(cn=testgroup1))" \
		dn cn userpassword gidnumber memberuid |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixgroup)(gidnumber=3456))" \
		dn cn userpassword gidnumber memberuid |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixgroup)(cn=testgroup2))" \
		dn cn userpassword gidnumber memberuid |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixgroup)(gidnumber=34567))" \
		dn cn userpassword gidnumber memberuid |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixgroup)(cn=testgroup3, for real))" \
		dn cn userpassword gidnumber memberuid |\
	$LDIFSORT
	search -b cn=compat,cn=accounts,dc=example,dc=com \
		"(&(objectclass=posixgroup)(gidnumber=345678))" \
		dn cn userpassword gidnumber memberuid |\
	$LDIFSORT
}

# Initialize the user database.
echo -n > "$WRAPPERS_PASSWD"
echo -n > "$WRAPPERS_GROUP"

# Test that we can't see these users.
echo '[nothing]'
searches

# Add the entries.
echo "$testuser1" >> "$WRAPPERS_PASSWD"
echo "$testuser2" >> "$WRAPPERS_PASSWD"
echo "$testuser3" >> "$WRAPPERS_PASSWD"
echo "$testgroup1" >> "$WRAPPERS_GROUP"
echo "$testgroup2" >> "$WRAPPERS_GROUP"
echo "$testgroup3" >> "$WRAPPERS_GROUP"

# Test that we can see these users and groups now.
echo '[all entries]'
searches

# Nuke the entries.
echo -n > "$WRAPPERS_PASSWD"
echo -n > "$WRAPPERS_GROUP"

# Test that we can still see these users, since they're in the cache now.
echo '[all entries]'
searches

# Try to bind to each of the group entries in turn, and test that we can no
# longer see the groups, since they should've been thrown out of the cache.
echo -n > wrap_pam
echo "[auth to testgroup1]"
simplebind -D 'cn=testgroup1,cn=groups,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w nope
echo "[auth to testgroup2]"
simplebind -D 'cn=testgroup2,cn=groups,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w nope
echo "[auth to testgroup3, for real]"
simplebind -D 'cn=testgroup3\2C for real,cn=groups,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w nope
echo '[just users]'
searches

# Try to bind to each of the user entries in turn.
cat > wrap_pam << EOF
testuser1:authtok:0:0
testuser2:authtok:0:0
testuser3, for real:authtok:SUCCESS:NEW_AUTHTOK_REQD
EOF
echo "[auth:AUTH_ERR]"
simplebind -D 'uid=testuser1,cn=users,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w nope
echo "[auth:OK]"
simplebind -D 'uid=testuser2,cn=users,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w authtok
echo "[acct:NEW_AUTHTOK_REQD]"
simplebind -D 'uid=testuser3\2C for real,cn=users,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w authtok

# Test that we can still see the users.
echo '[still just users]'
searches

# Try to bind to each of the entries in turn.
cat > wrap_pam << EOF
testuser1:authtok:MAXTRIES
testuser2:authtok:PERM_DENIED
testuser3, for real:authtok:0:ACCT_EXPIRED
EOF
echo "[auth:MAXTRIES]"
simplebind -D 'uid=testuser1,cn=users,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w authtok
echo "[auth:PERM_DENIED]"
simplebind -D 'uid=testuser2,cn=users,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w authtok
echo "[acct:ACCT_EXPIRED]"
simplebind -D 'uid=testuser3\2C for real,cn=users,cn=compat,cn=accounts,dc=example,dc=com' \
	   -w authtok

# Test that we can still see just the users.
echo '[yup, still just users]'
searches
