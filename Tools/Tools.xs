/* ToolKit.xs
 *
 * Copyright 2003, Michael Robinton <michael@bizsystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bdbtarpit.h"

#define DBTP_U32size sizeof(u_int32_t)


DBTPD dbtp;

#define _t_seterr(erp,err) \
	(erp) = get_sv("IPTables::IPv4::DBTarpit::Tools::DBTP_ERROR", FALSE); \
	if ((erp) != NULL) { \
	    (err) = dbtp.dberr; \
	    sv_setiv((erp),(err)); \
	}

int run_recovery = 0;

#include "c_includes/alt_inet_aton.c"

MODULE = IPTables::IPv4::DBTarpit::Tools	PACKAGE = IPTables::IPv4::DBTarpit::Tools

PROTOTYPES: DISABLE

 # include functions for inet_aton, inet_ntoa

INCLUDE: xs_include/miniSocket.inc

int
t_set_recovery(val)
	int val
    CODE:
	RETVAL = run_recovery;
	run_recovery = val;
    OUTPUT:
	RETVAL

int
t_new(home,...)
	char * home
    PREINIT:
	STRLEN len;
	int i, index;
	SV * erp;
	IV err;
    CODE:
	if (items < 2) {
	    dbtp.dberr = DB_NOTFOUND;
	    _t_seterr(erp,err);
	    XSRETURN_UNDEF;
	}

	dbtp_close(&dbtp);	/* just in case	*/

	for(i=1;i<items;i++) {
	    dbtp.dbfile[i-1] = (u_char *)SvPV(ST(i),len);
	}
	if (run_recovery)
	    index = DB_RUNRECOVERY;
	else
	    index = -1;
	RETVAL = dbtp_init(&dbtp,home,index);
	_t_seterr(erp,err);

    OUTPUT:
	RETVAL

void
t_closedb()
    PREINIT:
	SV * erp;
	IV err;
    CODE:
	dbtp_close(&dbtp);
	_t_seterr(erp,err);

 # if ai < notstring, get U32, else get string
SV *
t_get(ai,addr,notstring)
	int ai
	SV * addr
	int notstring
    PREINIT:
	STRLEN len;
	void * adp;
	int rv;
	SV * val, * erp;
	IV err;
    PPCODE:
	adp = (void *)SvPV(addr,len);
	rv = dbtp_get(&dbtp,ai,adp,len);
	_t_seterr(erp,err);

	if (rv == DB_NOTFOUND)
	    XSRETURN_UNDEF;
	else if (rv)
	    XSRETURN_IV(0);

	if (ai < notstring && dbtp.mgdbt.size == DBTP_U32size) {
	    val = newSViv(*(U32 *)dbtp.mgdbt.data);
	    sv_setuv(val,*(U32 *)dbtp.mgdbt.data);
	    XPUSHs(sv_2mortal(val));
	}
	else
	    XPUSHs(sv_2mortal(newSVpv(dbtp.mgdbt.data,dbtp.mgdbt.size)));
	XSRETURN(1);


 # if ai < notstring, get U32, else get string
void
t_getrecno(ai,cursor,notstring)
	int ai
	U32 cursor
	int notstring
    PREINIT:
	int rv;
	SV * val, * erp;
	IV err;
    PPCODE:
	rv = dbtp_getrecno(&dbtp,ai,cursor);
	_t_seterr(erp,err);
	if (rv) {
	    if (GIMME == G_ARRAY)
		XSRETURN_EMPTY;
	    else
		XSRETURN_UNDEF;
	}

	XPUSHs(sv_2mortal(newSVpv(dbtp.keydbt.data,dbtp.keydbt.size)));

	if (GIMME == G_ARRAY) {
	    if (ai < notstring && dbtp.mgdbt.size == DBTP_U32size) {
		val = newSViv(*(U32 *)dbtp.mgdbt.data);
		sv_setuv(val,*(U32 *)dbtp.mgdbt.data);
		XPUSHs(sv_2mortal(val));
	    }
	    else
		XPUSHs(sv_2mortal(newSVpv(dbtp.mgdbt.data,dbtp.mgdbt.size)));
	    XSRETURN(2);
	}
	XSRETURN(1);

int
t_del(ai,addr)
	int ai
	SV * addr
    PREINIT:
	STRLEN len;
	void * adp;
	int rv;
	SV * erp;
	IV err;
    CODE:
	adp = (void *)SvPV(addr,len);
	rv = dbtp_del(&dbtp,ai,adp,len);
	_t_seterr(erp,err);

	if (rv == DB_NOTFOUND)
	    XSRETURN_UNDEF;

	RETVAL = rv;
    OUTPUT:
	RETVAL

 # if ai < notstring, put U32, else put string
int
t_put(ai,addr,val,notstring)
	int ai
	SV * addr
	SV * val
	int notstring
    PREINIT:
	STRLEN alen, vlen;
	void * adp, * vlp;
	int rv;
	SV * erp;
	IV err;
	U32 ival;
    CODE:
	adp = (void *)SvPV(addr,alen);

 # check for IV == number
	if (ai < notstring && SvNIOK(val)) {
	    ival = SvUV(val);
	    vlp = (void *)&ival;
	    vlen = DBTP_U32size;
	}
	else
	    vlp = (void *)SvPV(val,vlen);

	RETVAL = dbtp_put(&dbtp,ai,adp,alen,vlp,vlen);
	_t_seterr(erp,err);
    OUTPUT:
	RETVAL

int
t_sync(ai)
	int ai;
    PREINIT:
	SV * erp;
	IV err;
    CODE:
	RETVAL = dbtp_sync(&dbtp,ai);
	_t_seterr(erp,err);
    OUTPUT:
	RETVAL

char *
t_db_strerror(err)
	int err
    CODE:
	RETVAL = dbtp_strerror(err);
    OUTPUT:
	RETVAL

 # if ai < notstring, put U32, else put string
int
t_dump(ai,hp,notstring)
	int ai
	SV * hp
	int notstring
    PREINIT:
	U32 cursor;
	HV * hash;
	int rv;
	SV * val, * erp;
	IV err;
    CODE:
	if (!SvROK(hp)) {
	    rv = dbtp.dberr = DB_NOTFOUND;
	    _t_seterr(erp,err);
	    cursor = 0;
	}
	else {
	    cursor = 1;
	    hash = (HV *)SvRV(hp);
	    hv_clear(hash);
	    rv = 0;
	}
	while(cursor) {
	    rv = dbtp_getrecno(&dbtp,ai,cursor++);
	    if (rv) {
		if(rv == DB_NOTFOUND && cursor != 1)
		    rv = dbtp.dberr = 0;
		_t_seterr(erp,err);
		break;
	    }
	    if (ai < notstring  && dbtp.mgdbt.size == DBTP_U32size) {
		val = newSViv(*(U32 *)dbtp.mgdbt.data);
		sv_setuv(val,*(U32 *)dbtp.mgdbt.data);
	    }
	    else
		val = newSVpv(dbtp.mgdbt.data,dbtp.mgdbt.size);

	    (void)hv_store(hash,(char *)dbtp.keydbt.data,dbtp.keydbt.size,val,0);
 #	    SvREFCNT_dec(val);
	}

	RETVAL = rv;
    OUTPUT:
	RETVAL

int
t_notfound()
    CODE:
	RETVAL = DB_NOTFOUND;
    OUTPUT:
	RETVAL

void
t_bdbversion()
    PREINIT:
	int major, minor, patch;
    PPCODE:
	XPUSHs(sv_2mortal(newSVpv(dbtp_bdbversion(&major,&minor,&patch),0)));
	if (GIMME == G_ARRAY) {
	    XPUSHs(sv_2mortal(newSViv((I32)major)));
	    XPUSHs(sv_2mortal(newSViv((I32)minor)));
	    XPUSHs(sv_2mortal(newSViv((I32)patch)));
	    XSRETURN(4);
	}
	XSRETURN(1);

void
t_libversion()
    PREINIT:
	int major, minor, patch;
    PPCODE:
	XPUSHs(sv_2mortal(newSVpv(dbtp_libversion(&major,&minor,&patch),0)));
	if (GIMME == G_ARRAY) {
	    XPUSHs(sv_2mortal(newSViv((I32)major)));
	    XPUSHs(sv_2mortal(newSViv((I32)minor)));
	    XPUSHs(sv_2mortal(newSViv((I32)patch)));
	    XSRETURN(4);
	}
	XSRETURN(1);

U32
t_nkeys(ai)
	int ai
    PREINIT:
	SV * erp;
	IV err;
    CODE:
	RETVAL = dbtp_stati(&dbtp,ai);
	_t_seterr(erp,err);
	if (dbtp.dberr)
	    XSRETURN_UNDEF;
    OUTPUT:
	RETVAL
