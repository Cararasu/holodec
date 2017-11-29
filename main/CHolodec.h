
#ifndef CHOLODEC_H
#define CHOLODEC_H

#include <stdint.h>

#define HOLODEC_PTR(type) typedef void* type;

HOLODEC_PTR(HArchitecture)
HOLODEC_PTR(HBinary)
HOLODEC_PTR(HFunction)
HOLODEC_PTR(HString)
HOLODEC_PTR(HRegister)
HOLODEC_PTR(HStack)
HOLODEC_PTR(HMemory)
HOLODEC_PTR(HCallingConvention)

struct HContext{
	HArchitecture arch;
	HBinary binary;
	HFunction function;
};
/*
		HString name;
		HString desc;
		uint64_t bitbase;
		uint64_t wordbase;

		HList<std::function<FunctionAnalyzer* (Binary*) >> functionanalyzerfactories;
		HIdList<Register> registers;

		HSparseIdList<Stack> stacks;
		
		HSparseIdList<Memory> memories;

		HSparseIdList<CallingConvention> callingconventions;

		HIdMap<HId, InstrDefinition> instrdefs;

		HSparseIdList<IRExpression> irExpressions;*/

extern struct Holodec{
	
	
	
	
	struct{
		HString (*get_name)(HArchitecture);
		HString (*get_description)(HArchitecture);
		uint64_t (*get_bitbase)(HArchitecture);
		uint64_t (*get_wordbase)(HArchitecture);
		
		HRegister (*get_register)(HArchitecture, uint64_t);
		uint64_t (*get_regcount)(HArchitecture);
		
		HStack (*get_stack)(HArchitecture, uint64_t);
		uint64_t (*get_stackcount)(HArchitecture);
		
		HCallingConvention (*get_cc)(HArchitecture, uint64_t);
		uint64_t (*get_cccount)(HArchitecture);
		
	}arch;
	
	struct{
		
	}reg;
	
	struct{
		const char* (*unpack_string)(HString);
		HString (*pack_string)(const char*);
		HString (*dup_string)(const char*);
	}misc;
	
}holodec;


#endif //CHOLODEC_H