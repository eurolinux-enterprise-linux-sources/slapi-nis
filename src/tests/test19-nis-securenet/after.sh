#!/bin/sh
$YP -h 127.0.0.1 maplist example.com
echo example.com passwd.byname
$YP -h 127.0.0.1 -c all example.com passwd.byname
echo example.com passwd.byuid
$YP -h 127.0.0.1 -c all example.com passwd.byuid
