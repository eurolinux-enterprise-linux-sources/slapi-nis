#!/bin/sh
$YP maplist example.com
echo example.com passwd.byname
$YP -c all example.com passwd.byname
echo example.com passwd.byuid
$YP -c all example.com passwd.byuid
