#!/usr/bin/python
#
# There's no command-line client in yp-tools, but python provides a function.
#
import nis
for map in nis.maps():
	print map
