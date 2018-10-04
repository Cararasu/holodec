
#ifndef CHOLODEC_H
#define CHOLODEC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "CHolodecHeader.h"

#define HOLODEC_PTR(type) \
	struct type;\
	typedef struct type type;

HOLODEC_PTR (HArchitecture)
HOLODEC_PTR (HBinary)
HOLODEC_PTR (HFunction)
HOLODEC_PTR (HRegister)
HOLODEC_PTR (HStack)
HOLODEC_PTR (HMemory)
HOLODEC_PTR (HCallingConvention)
HOLODEC_PTR (HInstrDefinition)

HOLODEC_PTR (HSSARepresentation)
HOLODEC_PTR (HSSABB)
HOLODEC_PTR (HSSAArgument)

typedef struct HSSAExpression HSSAExpression;

typedef uint32_t HId;

struct HSSAExpression {
	HSSARepresentation* ssaRep;
	HId exprId;
};


void holodec_init (void);
HArchitecture* holodec_get_arch (uint64_t index);
HArchitecture* holodec_get_arch_by_name (const char* name);
uint64_t holodec_get_archcount (void);

const char* arch_get_name (HArchitecture* arch);
const char* arch_get_description (HArchitecture* arch);
uint64_t arch_get_bitbase (HArchitecture* arch);
uint64_t arch_get_bytebase (HArchitecture* arch);

HRegister* arch_get_register (HArchitecture* arch, uint64_t index);
HRegister* arch_get_register_by_id (HArchitecture* arch, HId index);
uint64_t arch_get_regcount (HArchitecture* arch);

HStack* arch_get_stack (HArchitecture* arch, uint64_t index);
HStack* arch_get_stack_by_id (HArchitecture* arch, HId index);
uint64_t arch_get_stackcount (HArchitecture* arch);

HCallingConvention* arch_get_cc (HArchitecture* arch, uint64_t index);
HCallingConvention* arch_get_cc_by_id (HArchitecture* arch, HId index);
uint64_t arch_get_cccount (HArchitecture* arch);

HInstrDefinition* arch_get_instrdef (HArchitecture* arch, uint64_t index);
HInstrDefinition* arch_get_instrdef_by_id (HArchitecture* arch, HId index);
uint64_t arch_get_instrdefcount (HArchitecture* arch);



HSSABB* ssa_get_block (HSSARepresentation* rep, uint64_t index);
HSSABB* ssa_get_block_by_id (HSSARepresentation* rep, HId id);

uint64_t ssa_get_blockcount (HSSARepresentation* rep);

HSSAExpression* ssa_get_expr (HSSARepresentation* rep, uint64_t index);
HSSAExpression* ssa_get_expr_by_id (HSSARepresentation* rep, HId id);
uint64_t ssa_get_exprcount (HSSARepresentation* rep);

//SSABB
HId ssa_get_block_id (HSSABB* ssaBB);

HId ssa_get_blockexprid (HSSABB* ssaBB, uint64_t index);
uint64_t ssa_get_blockexprid_count (HSSABB* ssaBB);
HId* ssa_get_blockexprid_ptr (HSSABB* ssaBB);

HId ssa_get_block_fallthroughId (HSSABB* ssaBB);

HId ssa_get_inblock (HSSABB* ssaBB, uint64_t index);
HId* ssa_get_inblock_ptr (HSSABB* ssaBB);
uint64_t ssa_get_inblock_count (HSSABB* ssaBB);

HId ssa_get_outblock (HSSABB* ssaBB, uint64_t index);
HId* ssa_get_outblock_ptr (HSSABB* ssaBB);
uint64_t ssa_get_outblock_count (HSSABB* ssaBB);

uint64_t ssa_get_block_startaddr (HSSABB* ssaBB);
uint64_t ssa_get_block_endaddr (HSSABB* ssaBB);

//SSAExpression
HId ssa_get_expr_id (HSSAExpression ssaExpr);
HSSAExprType ssa_get_expr_type (HSSAExpression ssaExpr);
uint64_t ssa_get_expr_refcount (HSSAExpression ssaExpr);
HSSAType ssa_get_expr_rettype (HSSAExpression ssaExpr);

HSSAFlagType ssa_get_expr_flagtype (HSSAExpression ssaExpr);
HSSAOpType ssa_get_expr_optype (HSSAExpression ssaExpr);
HId ssa_get_expr_builtinid (HSSAExpression ssaExpr);

HSSALocation ssa_get_expr_locationtype (HSSAExpression ssaExpr);
HReference ssa_get_expr_locationref (HSSAExpression ssaExpr);

uint64_t ssa_get_expr_instraddr (HSSAExpression ssaExpr);

HSSAArgument* ssa_get_expr_arg (HSSAExpression ssaExpr, uint64_t index);
uint64_t ssa_get_expr_argcount (HSSAExpression ssaExpr);

#ifdef __cplusplus
}
#endif

#endif //CHOLODEC_H
