/*    caretx.c
 *
 *    Copyright (C) 2013
 *     by Larry Wall and others
 *
 *    You may distribute under the terms of either the GNU General Public
 *    License or the Artistic License, as specified in the README file.
 *
 */

/*
 *   'I do not know clearly,' said Frodo; 'but the path climbs, I think,
 * up into the mountains on the northern side of that vale where the old
 * city stands.  It goes up to a high cleft and so down to -- that which
 * is beyond.'
 *   'Do you know the name of that high pass?' said Faramir.
 *
 *     [p.691 of _The Lord of the Rings_, IV/xi: "The Forbidden Pool"]
 */

/* This file contains a single function, set_caret_X, to set the $^X
 * variable.  It's only used in perl.c, but has various OS dependencies,
 * so its been moved to its own file to reduce header pollution.
 * See RT 120314 for details.
 */

#if defined(PERL_IS_MINIPERL) && !defined(USE_SITECUSTOMIZE)
#  define USE_SITECUSTOMIZE
#endif

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifdef NETWARE
#include "nwutil.h"
#endif

#ifdef USE_KERN_PROC_PATHNAME
#  include <sys/sysctl.h>
#endif

#ifdef USE_NSGETEXECUTABLEPATH
# include <mach-o/dyld.h>
#endif

/* Note: Functions in this file must not have bool parameters.  When
   PERL_BOOL_AS_CHAR is #defined, mach-o/dyld.h overrides it in this file
   by #including stdbool.h, so the function parameters here would conflict
   with those in proto.h.
*/

void
Perl_set_caret_X(pTHX) {
    GV* tmpgv = gv_fetchpvs("\030", GV_ADD|GV_NOTQUAL, SVt_PV); /* $^X */
    SV *const caret_x = GvSV(tmpgv);
#if defined(OS2)
    sv_setpv(caret_x, os2_execname(aTHX));
#else
    sv_setpv(caret_x, PL_origargv[0]);
#endif
}

/*
 * ex: set ts=8 sts=4 sw=4 et:
 */
