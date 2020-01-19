#!/bin/sh
echo map list:
$YP maplist example.com
$YP -c maplist example.com
for map in name2mac mac2name ; do
	echo all contents of example.com:"$map":
	$YP -c all example.com $map | LANG=C sort
	echo cat contents of example.com:"$map":
	$YP cat example.com $map | LANG=C sort
done
