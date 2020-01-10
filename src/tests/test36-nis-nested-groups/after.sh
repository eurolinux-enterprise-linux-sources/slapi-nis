#!/bin/sh
echo map list:
$YP maplist example.com
$YP -c maplist example.com
for map in `$YP maplist example.com` ; do
	echo contents of example.com:"$map":
	$YP cat example.com $map
done
