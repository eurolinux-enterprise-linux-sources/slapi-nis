#!/bin/sh
source ${builddir:-.}/slapd.sh
showdiff()
{
	base1=`basename "$1"`
	base2=`basename "$2"`
	diff -u "$@" | \
	sed -r -e "s,^--- .*/(.*),--- \1,g" -e "s,^\+\+\+ .*/(.*),+++ \1,g"
}
for subdir in "$@" ; do
	pushd $subdir > /dev/null
	TEST="$subdir"
	precmd=
	if ! $TESTS_USE_REFINT ; then
		if test -s $TESTDIR/$TEST/plugin-need-refint.txt ; then
			echo Skipping "$TEST", needs the refint plugin.
			continue
		fi
	fi
	if ! $TESTS_USE_MEMBEROF ; then
		if test -s $TESTDIR/$TEST/plugin-need-memberof.txt ; then
			echo Skipping "$TEST", needs the memberof plugin.
			continue
		fi
	fi
	if ! $TESTS_USE_MANAGED_ENTRIES ; then
		if test -s $TESTDIR/$TEST/plugin-need-mep.txt ; then
			echo Skipping "$TEST", needs the managed entries plugin.
			continue
		fi
	fi
	if test -x edit-dse-config.sh ; then
		precmd="$TESTDIR/$subdir/edit-dse-config.sh $BTESTDIR/config/dse.ldif"
	fi
	startslapd $TESTDIR/$subdir/dse.ldif $TESTDIR/$subdir/userRoot.ldif "$precmd"
	if test -x $TESTDIR/$subdir/before.sh ; then
		sleep 5
		$TESTDIR/$subdir/before.sh > before.out 2>&1
		if test -r $TESTDIR/$subdir/before.txt ; then
			if ! cmp -s $TESTDIR/$subdir/before.txt before.out ; then
				echo `basename "$subdir"`:
				showdiff $TESTDIR/$subdir/before.txt before.out
				stopslapd
				exit 1
			fi
		fi
	fi
	if test -x $TESTDIR/$subdir/change.sh ; then
		$TESTDIR/$subdir/change.sh > change.out 2>&1
		if test -r $TESTDIR/$subdir/change.txt ; then
			if ! cmp -s $TESTDIR/$subdir/change.txt change.out ; then
				echo `basename "$subdir"`:
				showdiff $TESTDIR/$subdir/change.txt change.out
				stopslapd
				exit 1
			fi
		fi
	fi
	if test -x $TESTDIR/$subdir/after.sh ; then
		sleep 5
		$TESTDIR/$subdir/after.sh > after.out 2>&1
		if test -r $TESTDIR/$subdir/after.txt ; then
			if ! cmp -s $TESTDIR/$subdir/after.txt after.out ; then
				echo `basename "$subdir"`:
				showdiff $TESTDIR/$subdir/after.txt after.out
				stopslapd
				exit 1
			fi
		fi
	fi
	if ! test -r $TESTDIR/$subdir/before.txt ; then
		if ! test -r $TESTDIR/$subdir/after.txt ; then
			if test -x $TESTDIR/$subdir/post.sh ; then
				if ! $TESTDIR/$subdir/post.sh $TESTDIR/$subdir/before.out $TESTDIR/$subdir/after.out ; then
					echo `basename "$subdir"`:
					showdiff $TESTDIR/$subdir/before.out after.out
					stopslapd
					exit 1
				fi
			fi
		fi
	fi
	stopslapd
	popd > /dev/null
	if test -s $TESTDIR/$subdir/description.txt ; then
		echo `basename $subdir`" ("`head -n 1 $TESTDIR/$subdir/description.txt`")": OK
	else
		echo `basename $subdir`: OK
	fi
done
exit 0
