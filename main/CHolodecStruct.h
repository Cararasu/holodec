#ifndef CHOLODECSTRUCT_H
#define CHOLODECSTRUCT_H


#include "CHolodecHeader.h"

extern const struct Holodec_struct{
	
	void (*init)(void);
	
	HArchitecture (*get_arch)(uint64_t);
	HArchitecture (*get_arch_by_name)(const char*);
	uint64_t (*get_archcount)(void);
	
	struct{
		const char* (*get_name)(HArchitecture*);
		const char* (*get_description)(HArchitecture*);
		uint64_t (*get_bitbase)(HArchitecture*);
		uint64_t (*get_wordbase)(HArchitecture*);
		
		HRegister* (*get_register)(HArchitecture*, uint64_t);
		HRegister* (*get_register_by_id)(HArchitecture*, HId);
		uint64_t (*get_regcount)(HArchitecture*);
		
		HStack* (*get_stack)(HArchitecture*, uint64_t);
		HStack* (*get_stack_by_id)(HArchitecture*, HId);
		uint64_t (*get_stackcount)(HArchitecture*);
		
		HCallingConvention* (*get_cc)(HArchitecture*, uint64_t);
		HCallingConvention* (*get_cc_by_id)(HArchitecture*, HId);
		uint64_t (*get_cccount)(HArchitecture);
		
		HInstrDefinition* (*get_instrdef)(HArchitecture*, uint64_t);
		HInstrDefinition* (*get_instrdef_by_id)(HArchitecture*, HId);
		uint64_t (*get_instrdefcount)(HArchitecture*);
		
	}arch;
	
	struct{
		
	}reg;
	
	struct{
		//SSARepresentation
		HSSABB* (*get_block)(HSSARepresentation*, uint64_t);
		HSSABB* (*get_block_by_id)(HSSARepresentation*, HId);
		uint64_t (*get_blockcount)(HSSARepresentation*);
		
		HSSAExpression* (*get_expr)(HSSARepresentation*, uint64_t);
		HSSAExpression* (*get_expr_by_id)(HSSARepresentation*, HId);
		uint64_t (*get_exprcount)(HSSARepresentation*);
		
		//SSABB
		HId (*get_block_id)(HSSABB*);
		
		HId (*get_blockexprid)(HSSABB*, uint64_t);
		uint64_t (*get_blockexprid_count)(HSSABB*);
		HId* (*get_blockexprid_ptr)(HSSABB*);
		
		HId (*get_block_fallthroughId)(HSSABB*);
		
		HId (*get_inblockid)(HSSABB*, uint64_t);
		uint64_t (*get_inblockid_count)(HSSABB*);
		
		HId (*get_outblockid)(HSSABB*, uint64_t);
		uint64_t (*get_outblockid_count)(HSSABB*);
		
		uint64_t (*get_block_startaddr)(HSSABB*);
		uint64_t (*get_block_endaddr)(HSSABB*);
		
		HId (*get_inblock)(HSSABB*, uint64_t);
		uint64_t (*get_inblock_count)(HSSABB*);
		
		HId (*get_outblock)(HSSABB*, uint64_t);
		uint64_t (*get_outblock_count)(HSSABB*);
		
		//SSAExpression
		HId (*get_expr_id)(HSSAExpression*);
		HSSAExprType (*get_expr_type)(HSSAExpression*);
		uint64_t (*get_expr_refcount)(HSSAExpression*);
		HSSAType (*get_expr_rettype)(HSSAExpression*);
		
		HSSAFlagType (*get_expr_flagtype)(HSSAExpression*);
		HSSAOpType (*get_expr_optype)(HSSAExpression*);
		HId (*get_expr_builtinid)(HSSAExpression*);
		
		HSSAExprLocation (*get_expr_locationtype)(HSSAExpression*);
		HReference (*get_expr_locationref)(HSSAExpression*);
		
		uint64_t (*get_expr_instraddr)(HSSAExpression*);
		
		HSSAArgument (*get_expr_arg)(HSSAExpression*, uint64_t);
		uint64_t (*get_expr_argcount)(HSSAExpression*);
		
	}ssa;
	
	struct{
		/*
		const char* (*unpack_string)(HString);
		HString (*pack_string)(const char*);
		HString (*dup_string)(const char*);*/
	}misc;
	
} Holodec;


#endif // CHOLODECSTRUCT_H
