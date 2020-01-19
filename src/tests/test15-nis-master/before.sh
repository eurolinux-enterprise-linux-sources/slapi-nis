#!/bin/sh
echo master 1 example.com passwd.byname
$YP master example.com passwd.byname
echo $?
echo master 2 example.com passwd.byname
$YP -c master example.com passwd.byname
echo $?
echo master 1 example.com bogus-map
$YP master example.com bogus-map
echo $?
echo master 2 example.com bogus-map
$YP -c master example.com bogus-map
echo $?
echo master 1 example2.com passwd.byname
$YP master example2.com passwd.byname
echo $?
echo master 2 example2.com passwd.byname
$YP -c master example2.com passwd.byname
echo $?
echo order 1 example.com passwd.byname
order=`$YP order example.com passwd.byname`
echo $?
now=`date +%s`
age=`expr ${now:-0} - ${order:-0}`
if test "$age" -lt 60 ; then
	echo OK: age -lt 60
else
	echo NOT OK: age -ge 60
fi
echo order 2 example.com passwd.byname
order=`$YP -c order example.com passwd.byname`
echo $?
now=`date +%s`
age=`expr ${now:-0} - ${order:-0}`
if test "$age" -lt 60 ; then
	echo OK: age -lt 60
else
	echo NOT OK: age -ge 60
fi
echo order 1 example.com bogus-map
$YP order example.com bogus-map
echo $?
echo order 2 example.com bogus-map
$YP -c order example.com bogus-map
echo $?
echo order 1 example2.com bogus-map
$YP order example2.com passwd.byname
echo $?
echo order 2 example2.com bogus-map
$YP -c order example2.com passwd.byname
echo $?
