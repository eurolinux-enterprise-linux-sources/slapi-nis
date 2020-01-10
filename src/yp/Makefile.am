CLEANFILES = yp.h yp_xdr.c yp_clnt.c

all: $(CLEANFILES)

yp.h: yp.x
	$(RM) -f $@
	$(RPCGEN) -h -o $@ $^
yp_xdr.c: yp.x
	$(RM) -f $@
	$(RPCGEN) -c -o $@ $^
yp_clnt.c: yp.x
	$(RM) -f $@
	$(RPCGEN) -l -o $@ $^
