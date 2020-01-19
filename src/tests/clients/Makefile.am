EXTRA_DIST = ypmaplist.py
AM_CFLAGS = @TIRPC_CFLAGS@ @RPC_CFLAGS@ -I../../yp
CLEANFILES = yp.h yp_xdr.c yp_clnt.c

noinst_PROGRAMS = yp ldifsort
BUILT_SOURCES = yp.h yp_clnt.c yp_xdr.c
yp_SOURCES = yp.c yp.h yp_clnt.c yp_xdr.c
yp_LDADD = @TIRPC_LIBS@ @RPC_LIBS@

yp.h: ../../yp/yp.x
	$(RM) -f $@
	$(RPCGEN) -h -o $@ $^
yp_xdr.c: ../../yp/yp.x
	$(RM) -f $@
	$(RPCGEN) -c -o $@ $^
yp_clnt.c: ../../yp/yp.x
	$(RM) -f $@
	$(RPCGEN) -l -o $@ $^
