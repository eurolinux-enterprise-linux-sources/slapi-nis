/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "../../yp/yp.h"

bool_t
xdr_ypstat (XDR *xdrs, ypstat *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypxfrstat (XDR *xdrs, ypxfrstat *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_domainname (XDR *xdrs, domainname *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, objp, YPMAXDOMAIN))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_mapname (XDR *xdrs, mapname *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, objp, YPMAXMAP))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_peername (XDR *xdrs, peername *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, objp, YPMAXPEER))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_keydat (XDR *xdrs, keydat *objp)
{
	register int32_t *buf;

	 if (!xdr_bytes (xdrs, (char **)&objp->keydat_val, (u_int *) &objp->keydat_len, YPMAXRECORD))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_valdat (XDR *xdrs, valdat *objp)
{
	register int32_t *buf;

	 if (!xdr_bytes (xdrs, (char **)&objp->valdat_val, (u_int *) &objp->valdat_len, YPMAXRECORD))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypmap_parms (XDR *xdrs, ypmap_parms *objp)
{
	register int32_t *buf;

	 if (!xdr_domainname (xdrs, &objp->domain))
		 return FALSE;
	 if (!xdr_mapname (xdrs, &objp->map))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->ordernum))
		 return FALSE;
	 if (!xdr_peername (xdrs, &objp->peer))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypreq_key (XDR *xdrs, ypreq_key *objp)
{
	register int32_t *buf;

	 if (!xdr_domainname (xdrs, &objp->domain))
		 return FALSE;
	 if (!xdr_mapname (xdrs, &objp->map))
		 return FALSE;
	 if (!xdr_keydat (xdrs, &objp->key))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypreq_nokey (XDR *xdrs, ypreq_nokey *objp)
{
	register int32_t *buf;

	 if (!xdr_domainname (xdrs, &objp->domain))
		 return FALSE;
	 if (!xdr_mapname (xdrs, &objp->map))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypreq_xfr (XDR *xdrs, ypreq_xfr *objp)
{
	register int32_t *buf;

	 if (!xdr_ypmap_parms (xdrs, &objp->map_parms))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->transid))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->prog))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->port))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypresp_val (XDR *xdrs, ypresp_val *objp)
{
	register int32_t *buf;

	 if (!xdr_ypstat (xdrs, &objp->stat))
		 return FALSE;
	 if (!xdr_valdat (xdrs, &objp->val))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypresp_key_val (XDR *xdrs, ypresp_key_val *objp)
{
	register int32_t *buf;

	 if (!xdr_ypstat (xdrs, &objp->stat))
		 return FALSE;
	 if (!xdr_valdat (xdrs, &objp->val))
		 return FALSE;
	 if (!xdr_keydat (xdrs, &objp->key))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypresp_master (XDR *xdrs, ypresp_master *objp)
{
	register int32_t *buf;

	 if (!xdr_ypstat (xdrs, &objp->stat))
		 return FALSE;
	 if (!xdr_peername (xdrs, &objp->peer))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypresp_order (XDR *xdrs, ypresp_order *objp)
{
	register int32_t *buf;

	 if (!xdr_ypstat (xdrs, &objp->stat))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->ordernum))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypresp_all (XDR *xdrs, ypresp_all *objp)
{
	register int32_t *buf;

	 if (!xdr_bool (xdrs, &objp->more))
		 return FALSE;
	switch (objp->more) {
	case TRUE:
		 if (!xdr_ypresp_key_val (xdrs, &objp->ypresp_all_u.val))
			 return FALSE;
		break;
	case FALSE:
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_ypresp_xfr (XDR *xdrs, ypresp_xfr *objp)
{
	register int32_t *buf;

	 if (!xdr_u_int (xdrs, &objp->transid))
		 return FALSE;
	 if (!xdr_ypxfrstat (xdrs, &objp->xfrstat))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypmaplist (XDR *xdrs, ypmaplist *objp)
{
	register int32_t *buf;

	 if (!xdr_mapname (xdrs, &objp->map))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->next, sizeof (ypmaplist), (xdrproc_t) xdr_ypmaplist))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypresp_maplist (XDR *xdrs, ypresp_maplist *objp)
{
	register int32_t *buf;

	 if (!xdr_ypstat (xdrs, &objp->stat))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->maps, sizeof (ypmaplist), (xdrproc_t) xdr_ypmaplist))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_yppush_status (XDR *xdrs, yppush_status *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_yppushresp_xfr (XDR *xdrs, yppushresp_xfr *objp)
{
	register int32_t *buf;

	 if (!xdr_u_int (xdrs, &objp->transid))
		 return FALSE;
	 if (!xdr_yppush_status (xdrs, &objp->status))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypbind_resptype (XDR *xdrs, ypbind_resptype *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypbind_binding (XDR *xdrs, ypbind_binding *objp)
{
	register int32_t *buf;

	int i;
	 if (!xdr_opaque (xdrs, objp->ypbind_binding_addr, 4))
		 return FALSE;
	 if (!xdr_opaque (xdrs, objp->ypbind_binding_port, 2))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_ypbind_resp (XDR *xdrs, ypbind_resp *objp)
{
	register int32_t *buf;

	 if (!xdr_ypbind_resptype (xdrs, &objp->ypbind_status))
		 return FALSE;
	switch (objp->ypbind_status) {
	case YPBIND_FAIL_VAL:
		 if (!xdr_u_int (xdrs, &objp->ypbind_resp_u.ypbind_error))
			 return FALSE;
		break;
	case YPBIND_SUCC_VAL:
		 if (!xdr_ypbind_binding (xdrs, &objp->ypbind_resp_u.ypbind_bindinfo))
			 return FALSE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

bool_t
xdr_ypbind_setdom (XDR *xdrs, ypbind_setdom *objp)
{
	register int32_t *buf;

	 if (!xdr_domainname (xdrs, &objp->ypsetdom_domain))
		 return FALSE;
	 if (!xdr_ypbind_binding (xdrs, &objp->ypsetdom_binding))
		 return FALSE;
	 if (!xdr_u_int (xdrs, &objp->ypsetdom_vers))
		 return FALSE;
	return TRUE;
}
