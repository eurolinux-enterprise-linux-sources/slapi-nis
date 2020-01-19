#!/bin/sh
echo domain example.com
$YP domain example.com
echo domain example2.com
$YP domain example2.com
echo maplist 1 example.com
$YP maplist example.com
echo maplist 2 example.com
$YP -c maplist example.com
echo maplist 1 example2.com
$YP maplist example2.com
echo maplist 2 example2.com
$YP -c maplist example2.com
