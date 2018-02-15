

#include "Architecture.h"
#include "Main.h"

extern "C" {
#include "CHolodec.h"
}
	void holodec_init (void) {
		holodec::Main::initMain();
	}
	HArchitecture* holodec_get_arch (uint64_t index) {
		return reinterpret_cast<HArchitecture*> (holodec::Main::g_main->architectures[index]);
	}
	HArchitecture* holodec_get_arch_by_name (const char* name) {
		return reinterpret_cast<HArchitecture*> (holodec::Main::g_main->getArchitecture (name));
	}
	uint64_t holodec_get_archcount (void) {
		return holodec::Main::g_main->architectures.size();
	}

	const char* arch_get_name (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->name.cstr();
	}
	const char* arch_get_description (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->desc.cstr();
	}
	uint64_t arch_get_bitbase (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->bitbase;
	}
	uint64_t arch_get_wordbase (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->wordbase;
	}

	HRegister* arch_get_register (HArchitecture* arch, uint64_t index) {
		return reinterpret_cast<HRegister*> (&reinterpret_cast<holodec::Architecture*> (arch)->registers.list[index]);
	}
	HRegister* arch_get_register_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HRegister*> (&reinterpret_cast<holodec::Architecture*> (arch)->registers[index]);
	}
	uint64_t arch_get_regcount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->registers.size();
	}

	HStack* arch_get_stack (HArchitecture* arch, uint64_t index) {
		return reinterpret_cast<HStack*> (&reinterpret_cast<holodec::Architecture*> (arch)->stacks.list[index]);
	}
	HStack* arch_get_stack_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HStack*> (&reinterpret_cast<holodec::Architecture*> (arch)->stacks[index]);
	}
	uint64_t arch_get_stackcount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->stacks.size();
	}

	HCallingConvention* arch_get_cc (HArchitecture* arch, uint64_t index) {
		return reinterpret_cast<HCallingConvention*> (&reinterpret_cast<holodec::Architecture*> (arch)->callingconventions.list[index]);
	}
	HCallingConvention* arch_get_cc_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HCallingConvention*> (&reinterpret_cast<holodec::Architecture*> (arch)->callingconventions[index]);
	}
	uint64_t arch_get_cccount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->callingconventions.size();
	}

	HInstrDefinition* arch_get_instrdef (HArchitecture* arch, uint64_t index) {
		holodec::Architecture* a = reinterpret_cast<holodec::Architecture*> (arch);
		return reinterpret_cast<HInstrDefinition*> (&a->instrdefs[a->instrIds[index]]);
	}
	HInstrDefinition* arch_get_instrdef_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HInstrDefinition*> (&reinterpret_cast<holodec::Architecture*> (arch)->instrdefs.at (index));
	}
	uint64_t arch_get_instrdefcount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->instrdefs.size();
	}


	HSSABB* ssa_get_block (HSSARepresentation* rep, uint64_t index) {
		auto it = reinterpret_cast<holodec::SSARepresentation*> (rep)->bbs.list.begin();
		return reinterpret_cast<HSSABB*> (&* (it + index));
	}
	HSSABB* ssa_get_block_by_id (HSSARepresentation* rep, HId id) {
		return reinterpret_cast<HSSABB*> (reinterpret_cast<holodec::SSARepresentation*> (rep)->bbs.get (id));
	}

	uint64_t ssa_get_blockcount (HSSARepresentation* rep) {
		return reinterpret_cast<holodec::SSARepresentation*> (rep)->bbs.size();
	}

	HSSAExpression* ssa_get_expr (HSSARepresentation* rep, uint64_t index) {
		auto it = reinterpret_cast<holodec::SSARepresentation*> (rep)->expressions.list.begin();
		return reinterpret_cast<HSSAExpression*> (&* (it + index));
	}
	HSSAExpression* ssa_get_expr_by_id (HSSARepresentation* rep, HId id) {
		return reinterpret_cast<HSSAExpression*> (reinterpret_cast<holodec::SSARepresentation*> (rep)->expressions.get (id));
	}
	uint64_t ssa_get_exprcount (HSSARepresentation* rep) {
		return reinterpret_cast<holodec::SSARepresentation*> (rep)->expressions.size();
	}

//SSABB
	HId ssa_get_block_id (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->id;
	}

	HId ssa_get_blockexprid (HSSABB* ssaBB, uint64_t index) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->exprIds[index];
	}
	uint64_t ssa_get_blockexprid_count (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->exprIds.size();
	}
	HId* ssa_get_blockexprid_ptr (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->exprIds.data();
	}

	HId ssa_get_block_fallthroughId (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->fallthroughId;
	}

	HId ssa_get_inblock (HSSABB* ssaBB, uint64_t index) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->inBlocks[index];
	}
	HId* ssa_get_inblock_ptr (HSSABB* ssaBB) {
		return &*reinterpret_cast<holodec::SSABB*> (ssaBB)->inBlocks.begin();
	}
	uint64_t ssa_get_inblock_count (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->inBlocks.size();
	}

	HId ssa_get_outblock (HSSABB* ssaBB, uint64_t index) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->outBlocks[index];
	}
	HId* ssa_get_outblock_ptr (HSSABB* ssaBB) {
		return &*reinterpret_cast<holodec::SSABB*> (ssaBB)->outBlocks.begin();
	}
	uint64_t ssa_get_outblock_count (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->outBlocks.size();
	}

	uint64_t ssa_get_block_startaddr (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->startaddr;
	}
	uint64_t ssa_get_block_endaddr (HSSABB* ssaBB) {
		return reinterpret_cast<holodec::SSABB*> (ssaBB)->endaddr;
	}

	//SSAExpression
	HId ssa_get_expr_id (HSSAExpression ssaExpr){
		return ssaExpr.exprId;
	}
	HSSAExprType ssa_get_expr_type (HSSAExpression ssaExpr){
		return static_cast<HSSAExprType>(reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].type);
	}
	HSSAType ssa_get_expr_rettype (HSSAExpression ssaExpr){
		return static_cast<HSSAType>(reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].exprtype);
	}

	HSSAFlagType ssa_get_expr_flagtype (HSSAExpression ssaExpr){
		return static_cast<HSSAFlagType>(reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].flagType);
	}
	HSSAOpType ssa_get_expr_optype (HSSAExpression ssaExpr){
		return static_cast<HSSAOpType>(reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].opType);
	}
	HId ssa_get_expr_builtinid (HSSAExpression ssaExpr){
		return reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].builtinId;
	}

	HSSAExprLocation ssa_get_expr_locationtype (HSSAExpression ssaExpr){
		return static_cast<HSSAExprLocation>(reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].location);
	}
	HReference ssa_get_expr_locationref (HSSAExpression ssaExpr){
		return static_cast<HReference>(reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].locref);
	}

	uint64_t ssa_get_expr_instraddr (HSSAExpression ssaExpr){
		return reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].instrAddr;
	}

	HSSAArgument* ssa_get_expr_arg (HSSAExpression ssaExpr, uint64_t index){
		return reinterpret_cast<HSSAArgument*>(&reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].subExpressions[index]);
	}
	uint64_t ssa_get_expr_argcount (HSSAExpression ssaExpr){
		return reinterpret_cast<holodec::SSARepresentation*> (ssaExpr.ssaRep)->expressions[ssaExpr.exprId].subExpressions.size();
	}