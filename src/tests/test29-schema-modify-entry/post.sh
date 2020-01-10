#!/bin/sh
test `diff -u "$1" "$2" | grep ^-sequence: | wc -l` -eq 2 && \
test `diff -u "$1" "$2" | grep ^+sequence: | wc -l` -eq 2
