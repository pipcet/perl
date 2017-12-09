#include "EXTERN.h"
#include "perl.h"

#define DEBUG
#include "js-config.h"
#include "jsapi.h"

#include "js/Class.h"
#include "js/Initialization.h"
#include "js/RootingAPI.h"
#include "js/Conversions.h" // as of SpiderMonkey 38; previously in jsapi.h
#include "jsapi.h"

#include "regcomp.h"

#undef fprintf
#undef stderr

JSG jsg __attribute__((init_priority(102)));

extern PerlInterpreter my_perl;
extern const struct mro_alg dfs_alg;

static void SV_trace(JSTracer *tracer, JSObject *obj)
{
  SV *sv = (SV *)JS_GetPrivate(obj);

  //fprintf (stderr, "tracing %p\n", sv);

  if (!sv)
    return;

  if (SvROK(sv))
    TraceEdge(tracer, &SvRV(sv)->sv_jsval, "reference");

  switch (SvTYPE(sv))
    {
    case SVt_PVAV: {
      SV **ary = AvARRAY(sv);
      SSize_t key = AvFILLp(sv);
      while (key > -1) {
        if (AvARRAY(sv)[key])
          TraceEdge(tracer, &AvARRAY(sv)[key]->sv_jsval, "array element");
        key--;
      }
      break;
    }
    case SVt_REGEXP: {
      REGEXP *rx = (REGEXP *)sv;
      struct regexp *r = ReANY(rx);
      if (r->mother_re)
        TraceEdge(tracer, &r->mother_re->sv_jsval, "mother re");
      else {
        if (RXp_PAREN_NAMES(r))
          TraceEdge(tracer, &RXp_PAREN_NAMES(r)->sv_jsval, "paren names");
        RXi_GET_DECL(r,ri);
        if (ri->data) {
          int n = ri->data->count;

          while (--n >= 0) {
            /* If you add a ->what type here, update the comment in regcomp.h */
            switch (ri->data->what[n]) {
            case 'a':
            case 'r':
            case 's':
            case 'S':
            case 'u':
              if (ri->data->data[n])
                TraceEdge(tracer, &((SV *)ri->data->data[n])->sv_jsval, "regexp data");
            break;
            case 'f':
              break;
            case 'l':
            case 'L':
              break;
            case 'T':
              break;
            case 't':
              break;
            default:
              Perl_croak(aTHX_ "panic: regfree data code '%c'",
                         ri->data->what[n]);
            }
          }
        }
      }

      if (r->substrs && r->substrs->data[0].substr)
        TraceEdge(tracer, &r->substrs->data[0].substr->sv_jsval, "regexp string");
      if (r->substrs && r->substrs->data[1].substr)
        TraceEdge(tracer, &r->substrs->data[1].substr->sv_jsval, "regexp string");
      if (r->saved_copy)
        TraceEdge(tracer, &r->saved_copy->sv_jsval, "regexp saved copy");
      if (r->qr_anoncv)
        TraceEdge(tracer, &r->qr_anoncv->sv_jsval, "regexp saved copy");
      break;
    }
    case SVt_PVLV: {
      if (LvTARG(sv))
        TraceEdge(tracer, &LvTARG(sv)->sv_jsval, "LvTARG");
      break;
    }
    case SVt_PVGV: {
      GV *gv = (GV *)sv;
      if (GvSV(gv)) {
        TraceEdge(tracer, &GvSV(gv)->sv_jsval, "GvSV");
      }
      if (GvCV(gv)) {
        TraceEdge(tracer, &GvCV(gv)->sv_jsval, "GvSV");
      }
      if (GvHV(gv)) {
        TraceEdge(tracer, &GvHV(gv)->sv_jsval, "GvSV");
      }
      if (GvAV(gv)) {
        TraceEdge(tracer, &GvAV(gv)->sv_jsval, "GvSV");
      }
      if (GvIOp(gv)) {
        TraceEdge(tracer, &GvIOp(gv)->sv_jsval, "GvIOp");
      }
      if (GvEGVx(gv)) {
        TraceEdge(tracer, &GvEGVx(gv)->sv_jsval, "GvSV");
      }
      break;
    }
    case SVt_PVHV: {
      if (0) {
      HV *hv = (HV *)sv;
      SSize_t hash;
      for (hash = 0; hash <= HvMAX(hv); hash++) {
        auto entry = (HvARRAY(hv))[hash];

        for (HE *he = entry; he; he = HeNEXT(he))
          if (HeKEY_hek(he)) {
            if ((HEK_FLAGS(HeKEY_hek(he)) & HVhek_UNSHARED)) {
              if (HeVAL(he))
                TraceEdge(tracer, &HeVAL(he)->sv_jsval, "hash entry value");
            } else
              while(1);
          }
      }
      }
      HV *hv = (HV *)sv;
      if (hv == PL_strtab)
        break;
      if (hv_iterinit (hv)) {
        HE *he;
        while ((he = hv_iternext (hv))) {
          if (HeVAL (he))
            TraceEdge(tracer, &HeVAL(he)->sv_jsval, "hash entry value");
          if (HeSVKEY (he))
            TraceEdge(tracer, &HeSVKEY(he)->sv_jsval, "hash SV key");
        }
      }
      if (SvOOK(hv)) {
        struct xpvhv_aux *aux = HvAUX(hv);
        if (aux->xhv_backreferences)
          TraceEdge(tracer, &aux->xhv_backreferences->sv_jsval, "backreferences");
        if (HvNAME(hv)) {
          if (aux->xhv_mro_meta) {
            SV *av = MRO_GET_PRIVATE_DATA(aux->xhv_mro_meta, &dfs_alg);
            if (av)
              TraceEdge(tracer, &av->sv_jsval, "MRO metadata");
            HV *isa = aux->xhv_mro_meta->isa;
            if (isa)
              TraceEdge(tracer, &isa->sv_jsval, "MRO ISA");
            HV *super = aux->xhv_mro_meta->super;
            if (super)
              TraceEdge(tracer, &super->sv_jsval, "MRO ISA");
            HV *mro_nextmethod = aux->xhv_mro_meta->mro_nextmethod;
            if (mro_nextmethod)
              TraceEdge(tracer, &mro_nextmethod->sv_jsval, "MRO ISA");
            HV *mro_linear_all = aux->xhv_mro_meta->mro_linear_all;
            if (mro_linear_all)
              TraceEdge(tracer, &mro_linear_all->sv_jsval, "MRO ISA");
            SV *mro_linear_current = aux->xhv_mro_meta->mro_linear_current;
            if (mro_linear_current)
              TraceEdge(tracer, &mro_linear_current->sv_jsval, "MRO ISA");
            CV *destroy = aux->xhv_mro_meta->destroy;
            if (destroy)
              TraceEdge(tracer, &destroy->sv_jsval, "MRO ISA");
          }
        }
      }
      break;
      }
    case SVt_PVCV:
      {
        if (CvSTASH(sv))
          TraceEdge(tracer, &CvSTASH(sv)->sv_jsval, "CV stash");
        if (CvGV(sv))
          TraceEdge(tracer, &CvGV(sv)->sv_jsval, "CV stash");
        if (CvOUTSIDE(sv))
          TraceEdge(tracer, &CvOUTSIDE(sv)->sv_jsval, "CV stash");
        if (CvISXSUB(sv)) {
          if (CvXSUBANY(sv).any_sv)
            TraceEdge(tracer, &CvXSUBANY(sv).any_sv->sv_jsval, "CV stash");
          break;
        }
        PADLIST *padlist = CvPADLIST(sv);
        if (padlist) {
          for (I32 ix = 0; ix <= PadlistMAX(padlist); ix++)
            TraceEdge(tracer, &PadlistARRAY(padlist)[ix]->sv_jsval, "CV PADLIST");
        }
        if (!CvISXSUB(sv) && CvROOT(sv))
          TraceEdge(tracer, &CvROOT(sv)->op_jsval, "root");
        if (!CvISXSUB(sv) && CvSTART(sv))
          TraceEdge(tracer, &CvSTART(sv)->op_jsval, "root");
      }
      break;
    }
  if (SvMAGICAL(sv)) {
    for (MAGIC *mg = SvMAGIC(sv); mg; mg = mg->mg_moremagic) {
      if (mg->mg_obj)
        TraceEdge(tracer, &mg->mg_obj->sv_jsval, "backrefs");
      if (mg->mg_len == HEf_SVKEY)
        TraceEdge(tracer, &((SV *)mg->mg_ptr)->sv_jsval, "backrefs");
    }
  }
}

static void SV_finalize(JSFreeOp* op, JSObject *obj)
{
  SV *sv = (SV *)JS_GetPrivate(obj);

  if (!sv)
    return;

  if (SvREFCNT(sv) > 0)
    {
      fprintf(stderr, "finalizing SV %p with refcount %d\n", sv,
              SvREFCNT(sv));
      *(int *)0 = 0;
    }
  else
    free(sv);
}

static JSClassOps SV_class_ops =
  {
   nullptr, nullptr, nullptr, nullptr,
   nullptr, nullptr, SV_finalize,
   nullptr, nullptr, nullptr, SV_trace,
  };

JSClass SV_class =
  {
   "SV", JSCLASS_HAS_PRIVATE|JSCLASS_FOREGROUND_FINALIZE, &SV_class_ops,
  };

static void OP_trace(JSTracer *tracer, JSObject *obj)
{
  OP *o = (OP *)JS_GetPrivate(obj);

  //  fprintf (stderr, "tracing %p\n", o);

  if (!o)
    return;

  switch (o->op_type) {
  case OP_NULL:	/* Was holding old type, if any. */
    /* FALLTHROUGH */
  case OP_ENTERTRY:
  case OP_ENTEREVAL:	/* Was holding hints. */
  case OP_ARGDEFELEM:	/* Was holding signature index. */
    break;
  default:
    break;
    /* FALLTHROUGH */
  case OP_GVSV:
  case OP_GV:
  case OP_AELEMFAST:
    if (cSVOPx(o)->op_sv)
      TraceEdge(tracer, &cSVOPx(o)->op_sv->sv_jsval, "OP_GV");
    break;
  case OP_METHOD_REDIR:
  case OP_METHOD_REDIR_SUPER:
    TraceEdge(tracer, &cMETHOPx(o)->op_rclass_sv->sv_jsval, "METHOP");
    /* FALLTHROUGH */
  case OP_METHOD_NAMED:
  case OP_METHOD_SUPER:
    TraceEdge(tracer, &cMETHOPx(o)->op_u.op_meth_sv->sv_jsval, "METHOP");
    break;
  case OP_CONST:
  case OP_HINTSEVAL:
    TraceEdge(tracer, &cSVOPx(o)->op_sv->sv_jsval, "CONST");
    break;
  case OP_DUMP:
  case OP_GOTO:
  case OP_NEXT:
  case OP_LAST:
  case OP_REDO:
    if (o->op_flags & (OPf_SPECIAL|OPf_STACKED|OPf_KIDS))
      break;
    /* FALLTHROUGH */
  case OP_TRANS:
  case OP_TRANSR:
    if (   (o->op_type == OP_TRANS || o->op_type == OP_TRANSR)
           && (o->op_private & (OPpTRANS_FROM_UTF|OPpTRANS_TO_UTF)))
      {
        TraceEdge(tracer, &cSVOPx(o)->op_sv->sv_jsval, "METHOP");
      }
    break;
  case OP_MULTIDEREF:
    {
      UNOP_AUX_item *items = cUNOP_AUXo->op_aux;
      UV actions = items->uv;
      bool last = 0;
      bool is_hash = FALSE;

      while (!last) {
        switch (actions & MDEREF_ACTION_MASK) {

        case MDEREF_reload:
          actions = (++items)->uv;
          continue;

        case MDEREF_HV_padhv_helem:
          is_hash = TRUE;
          /* FALLTHROUGH */
        case MDEREF_AV_padav_aelem:
          ++items;
          goto do_elem;

        case MDEREF_HV_gvhv_helem:
          is_hash = TRUE;
          /* FALLTHROUGH */
        case MDEREF_AV_gvav_aelem:
          ++items;
          goto do_elem;

        case MDEREF_HV_gvsv_vivify_rv2hv_helem:
          is_hash = TRUE;
          /* FALLTHROUGH */
        case MDEREF_AV_gvsv_vivify_rv2av_aelem:
          ++items;
          goto do_vivify_rv2xv_elem;

        case MDEREF_HV_padsv_vivify_rv2hv_helem:
          is_hash = TRUE;
          /* FALLTHROUGH */
        case MDEREF_AV_padsv_vivify_rv2av_aelem:
          ++items;
          goto do_vivify_rv2xv_elem;

        case MDEREF_HV_pop_rv2hv_helem:
        case MDEREF_HV_vivify_rv2hv_helem:
          is_hash = TRUE;
          /* FALLTHROUGH */
        do_vivify_rv2xv_elem:
        case MDEREF_AV_pop_rv2av_aelem:
        case MDEREF_AV_vivify_rv2av_aelem:
        do_elem:
          switch (actions & MDEREF_INDEX_MASK) {
          case MDEREF_INDEX_none:
            last = 1;
            break;
          case MDEREF_INDEX_const:
            if (is_hash) {
              TraceEdge(tracer, &(++items)->sv->sv_jsval, "const");
            }
            else
              items++;
            break;
          case MDEREF_INDEX_padsv:
            items++;
            break;
          case MDEREF_INDEX_gvsv:
            items++;
            break;
          }

          if (actions & MDEREF_FLAG_last)
            last = 1;
          is_hash = FALSE;

          break;
        default:
          assert(0);
          last = 1;
          break;

        } /* switch */

        actions >>= MDEREF_SHIFT;
      } /* while */

      /* start of malloc is at op_aux[-1], where the length is
       * stored */
    }
    break;
  case OP_SUBST:
    if (cPMOPo->op_pmreplrootu.op_pmreplroot)
      TraceEdge(tracer, &cPMOPo->op_pmreplrootu.op_pmreplroot->op_jsval, "pmreplroot");
    goto clear_pmop;

  case OP_SPLIT:
    if (     (o->op_private & OPpSPLIT_ASSIGN) /* @array  = split */
             && !(o->op_flags & OPf_STACKED))       /* @{expr} = split */
      {
        if (!(o->op_private & OPpSPLIT_LEX))
          TraceEdge(tracer, &MUTABLE_SV(cPMOPo->op_pmreplrootu.op_pmtargetgv)->sv_jsval, "regexp");
      }
    /* FALLTHROUGH */
  case OP_MATCH:
  case OP_QR:
  clear_pmop:
    if (PM_GETRE(cPMOPo))
      TraceEdge(tracer, &PM_GETRE(cPMOPo)->sv_jsval, "regexp");
    break;

  case OP_ARGCHECK:
    break;

  case OP_MULTICONCAT:
    break;
  }

  if (OP_CLASS(o) == OPclass_SVOP) {
    TraceEdge(tracer, &cSVOPx_sv(o)->sv_jsval, "OP SV");
  } else if (OP_CLASS(o) == OPclass_COP) {
    if (cCOPo->cop_stash)
      TraceEdge(tracer, &cCOPo->cop_stash->sv_jsval, "COP stash");
    if (cCOPo->cop_filegv)
      TraceEdge(tracer, &cCOPo->cop_filegv->sv_jsval, "COP stash");
  }
  if (o->op_sibparent)
    TraceEdge(tracer, &o->op_sibparent->op_jsval, "sibparent op");
  if (o->op_flags & OPf_KIDS)
    if (cUNOPo->op_first)
      TraceEdge(tracer, &cUNOPo->op_first->op_jsval, "child op");
  if (o->op_next)
    TraceEdge(tracer, &o->op_next->op_jsval, "next op");
}

static void OP_finalize(JSFreeOp* freeop, JSObject *obj)
{
  OP *op = (OP *)JS_GetPrivate(obj);

  if (!op)
    return;

  if (op->op_type != OP_FREED && op->op_type != OP_NULL)
    fprintf(stderr, "finalizing OP %p\n", op);
}

static JSClassOps OP_class_ops =
  {
   nullptr, nullptr, nullptr, nullptr,
   nullptr, nullptr, OP_finalize,
   nullptr, nullptr, nullptr, OP_trace,
  };

JSClass OP_class =
  {
   "OP", JSCLASS_HAS_PRIVATE|JSCLASS_FOREGROUND_FINALIZE, &OP_class_ops,
  };

extern void trace_savestack(JSTracer *);

static void trace_ops(JSTracer* tracer, OP* o)
{
}

static void js_gc_trace(JSTracer* tracer, void *)
{
  if (PL_subname)
    TraceEdge(tracer, &PL_subname->sv_jsval, "subname");
  if (PL_isarev)
    TraceEdge(tracer, &PL_isarev->sv_jsval, "subname");
  if (PL_registered_mros)
    TraceEdge(tracer, &PL_registered_mros->sv_jsval, "subname");
  if (PL_blockhooks)
    TraceEdge(tracer, &PL_blockhooks->sv_jsval, "subname");
  if (PL_custom_ops)
    TraceEdge(tracer, &PL_custom_ops->sv_jsval, "subname");
  if (PL_rs)
    TraceEdge(tracer, &PL_rs->sv_jsval, "subname");
  if (PL_curstackinfo) {
    for (PERL_SI *si = PL_curstackinfo; si; si = si->si_prev)
      TraceEdge(tracer, &si->si_stack->sv_jsval, "SI stack");
    for (PERL_SI *si = PL_curstackinfo->si_next; si; si = si->si_next)
      TraceEdge(tracer, &si->si_stack->sv_jsval, "SI stack");
  }
  if (PL_fdpid)
    TraceEdge(tracer, &PL_fdpid->sv_jsval, "subname");
  if (PL_modglobal)
    TraceEdge(tracer, &PL_modglobal->sv_jsval, "subname");
  if (PL_errors)
    TraceEdge(tracer, &PL_errors->sv_jsval, "subname");
  if (PL_strtab)
    TraceEdge(tracer, &PL_strtab->sv_jsval, "strtab");
  if (PL_stashcache)
    TraceEdge(tracer, &PL_stashcache->sv_jsval, "stashcache");
  if (PL_patchlevel)
    TraceEdge(tracer, &PL_patchlevel->sv_jsval, "stashcache");
#define T(sv) if (sv) TraceEdge(tracer, &(sv)->sv_jsval, #sv)
  T(PL_XPosix_ptrs[_CC_ASCII]);
  T(PL_XPosix_ptrs[_CC_ALPHANUMERIC]);
  T(PL_XPosix_ptrs[_CC_BLANK]);
  T(PL_XPosix_ptrs[_CC_ALPHA]);
  T(PL_XPosix_ptrs[_CC_CASED]);
  T(PL_XPosix_ptrs[_CC_CNTRL]);
  T(PL_XPosix_ptrs[_CC_DIGIT]);
  T(PL_XPosix_ptrs[_CC_GRAPH]);
  T(PL_XPosix_ptrs[_CC_LOWER]);
  T(PL_XPosix_ptrs[_CC_PRINT]);
  T(PL_XPosix_ptrs[_CC_PUNCT]);
  T(PL_XPosix_ptrs[_CC_SPACE]);
  T(PL_XPosix_ptrs[_CC_UPPER]);
  T(PL_XPosix_ptrs[_CC_VERTSPACE]);
  T(PL_XPosix_ptrs[_CC_WORDCHAR]);
  T(PL_XPosix_ptrs[_CC_XDIGIT]);
  T(PL_GCB_invlist);
  T(PL_SB_invlist);
  T(PL_WB_invlist);
  T(PL_LB_invlist);
  T(PL_Assigned_invlist);
  T(PL_curstname);
  T(PL_incgv);
  T(PL_hintgv);
  T(PL_defgv);
  T(PL_errgv);
  T(PL_replgv);
  T(PL_main_cv);
  T(PL_compcv);
  T(PL_comppad);
  T(PL_toptarget);
  T(PL_bodytarget);
  T(PL_formtarget);
  T(PL_statname);
  T(PL_beginav);
  T(PL_endav);
  T(PL_checkav);
  T(PL_unitcheckav);
  T(PL_AboveLatin1);
  T(PL_Latin1);
  T(PL_UpperLatin1);
  T(PL_utf8_foldable);
  T(PL_HasMultiCharFold);
  T(PL_InBitmap);

  if (PL_defstash)
    TraceEdge(tracer, &PL_defstash->sv_jsval, "defstash");
  if (PL_curstash)
    TraceEdge(tracer, &PL_curstash->sv_jsval, "curstash");
  if (PL_curpad && (*PL_curpad))
    TraceEdge(tracer, &(*PL_curpad)->sv_jsval, "curpad");
  if (PL_comppad)
    TraceEdge(tracer, &PL_comppad->sv_jsval, "comppad");
  TraceEdge(tracer, &PL_sv_immortals[0].sv_jsval, "immortal");
  TraceEdge(tracer, &PL_sv_immortals[1].sv_jsval, "immortal");
  TraceEdge(tracer, &PL_sv_immortals[2].sv_jsval, "immortal");
  TraceEdge(tracer, &PL_sv_immortals[3].sv_jsval, "immortal");
  if (PL_stack_base)
    for (SV **p = PL_stack_base; p < PL_stack_sp; p++)
      TraceEdge(tracer, &p[0]->sv_jsval, "stack var");
  /* this index is inclusive. */
  if (PL_tmps_stack)
    for (SV **p = PL_tmps_stack; p <= PL_tmps_stack + PL_tmps_ix; p++)
      TraceEdge(tracer, &p[0]->sv_jsval, "mortal var");

  trace_savestack(tracer);
  if (PL_curstackinfo && cxstack)
    for (I32 ix = cxstack_ix; ix >= 0; ix--) {
      PERL_CONTEXT *cx = &cxstack[ix];

      if (CxTYPE(cx) == CXt_SUB) {
        TraceEdge(tracer, &cx->blk_sub.savearray->sv_jsval, "saved defgv");
        TraceEdge(tracer, &cx->blk_sub.prevcomppad->sv_jsval, "saved comppad");
        TraceEdge(tracer, &cx->blk_sub.cv->sv_jsval, "saved CV");
      } else if (CxTYPE(cx) == CXt_EVAL) {
        if (cx->blk_eval.old_namesv)
          TraceEdge(tracer, &cx->blk_eval.old_namesv->sv_jsval, "saved defgv");
        if (cx->blk_eval.old_eval_root)
          TraceEdge(tracer, &cx->blk_eval.old_eval_root->op_jsval, "saved comppad");
        if (cx->blk_eval.cv)
          TraceEdge(tracer, &cx->blk_eval.cv->sv_jsval, "saved CV");
        if (cx->blk_eval.cur_text)
          TraceEdge(tracer, &cx->blk_eval.cur_text->sv_jsval, "saved CV");
        if (cx->blk_eval.retop)
          TraceEdge(tracer, &cx->blk_eval.retop->op_jsval, "saved CV");
      } else if (CxTYPE_is_LOOP(cx)) {
        if (cx->cx_type & (CXp_FOR_PAD|CXp_FOR_GV))
          if (cx->blk_loop.itersave)
            TraceEdge(tracer, &cx->blk_loop.itersave->sv_jsval, "itersave");
        if (CxTYPE(cx) == CXt_LOOP_ARY ||
            CxTYPE(cx) == CXt_LOOP_LAZYSV) {
          if (cx->blk_loop.state_u.lazysv.cur)
            TraceEdge(tracer, &cx->blk_loop.state_u.lazysv.cur->sv_jsval, "cur lazysv");
          if (CxTYPE(cx) == CXt_LOOP_LAZYSV && cx->blk_loop.state_u.lazysv.end)
            TraceEdge(tracer, &cx->blk_loop.state_u.lazysv.end->sv_jsval, "end lazysv");
        }
      }
    }

  if (PL_main_root)
    TraceEdge(tracer, &PL_main_root->op_jsval, "optree");
  if (PL_eval_root)
    TraceEdge(tracer, &PL_eval_root->op_jsval, "optree");
  for (I32 ix = 0; ix < SV_CONSTS_COUNT; ix++)
    if (PL_sv_consts[ix])
      TraceEdge(tracer, &PL_sv_consts[ix]->sv_jsval, "constant");
  if (PL_parser) {
    if (PL_parser->linestr)
      TraceEdge(tracer, &PL_parser->linestr->sv_jsval, "parser->linestr");
  }
}
static bool
global_enumerate(JSContext* cx, JS::HandleObject obj, JS::AutoIdVector& properties,
                 bool enumerableOnly)
{
    return true;
}

static bool
global_resolve(JSContext* cx, JS::HandleObject obj, JS::HandleId id, bool* resolvedp)
{
  *resolvedp = false;
  return true;
}

static bool
global_mayResolve(const JSAtomState& names, jsid id, JSObject* maybeObj)
{
    return JS_MayResolveStandardClass(names, id, maybeObj);
}

static const JSClassOps global_classOps = {
    nullptr, nullptr, nullptr,
    global_enumerate, global_resolve, global_mayResolve,
    nullptr,
    nullptr, nullptr, nullptr,
    JS_GlobalObjectTraceHook
};

static const JSClass global_class = {
    "global", JSCLASS_GLOBAL_FLAGS,
    &global_classOps
};


bool js_init()
{
  //js::DisableExtraThreads()

  if (!JS_Init())
    return false;

  JSContext *cx = JS_NewContext(64 * JS::DefaultHeapMaxBytes, JS::DefaultNurseryBytes);
  jsg.cx = cx;
  if (!cx)
    return false;
  //JS_SetFutexCanWait(cx);
  //JS::SetWarningReporter(cx, WarningReporter);
  //JS_SetGCParameter(cx, JSGC_MAX_BYTES, 0x1fffffffL);

  JS_SetNativeStackQuota(cx, 8 * 1024 * 1024);

  if (!JS::InitSelfHostedCode(cx))
    return false;

  JS_SetGCParameter(cx, JSGC_MODE, JSGC_MODE_INCREMENTAL);

  {
    JS_BeginRequest(cx);
    JS::CompartmentOptions compartment_options;
    JS::RootedObject glob(cx, JS_NewGlobalObject(cx, &global_class, nullptr, JS::FireOnNewGlobalHook, compartment_options));

    if (!glob)
      return false;

    {
      JS_EnterCompartment (cx, glob);
      if (!JS_InitStandardClasses(cx, glob))
        return false;
      JS_InitClass(cx, glob, nullptr, &SV_class, nullptr, 0,
                   nullptr, nullptr, nullptr, nullptr);
      JS_InitClass(cx, glob, nullptr, &OP_class, nullptr, 0,
                   nullptr, nullptr, nullptr, nullptr);
      JS_AddExtraGCRootsTracer(cx, js_gc_trace, NULL);
      //if (!JS_DefineFunctions(cx, glob, emacs_functions))
      //  return false;
      //elisp_classes_init(cx, glob);
      //elisp_gc_callback_register(cx);
      //JS_InitClass(cx, glob, nullptr, &cons_class, cons_construct, 2,
      //             nullptr, nullptr, nullptr, nullptr);
      //JS_InitClass(cx, glob, nullptr, &string_class, string_construct, 1,
      //             string_props, string_fns, nullptr, nullptr);
    }

  }

  return true;
}
