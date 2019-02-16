
#include "pch.h"
#include <iostream>

#include "String.h"
#include "Array.h"
#include "Parser.h"
#include <elfio/elfio.hpp>


/*
layer 0:
	file parser
layer 1:
	linear sweep basic block disassembler
	and address queue
	Datastructure
		basic blocks
		types
		locations
	controlled by IR-translation but does not create IR
layer 2:
	function compositor
layer 3:
	SSA-generation
layer 3.5:
	optimization passes
layer 4:
	AST-generation
layer 5:
	pseudo code

struct ABBTarget {
	size_t address;
	u32 certainty;
};
enum ABBJumpType {
	eBranch,
	eCall,
	eReturn
};
=($rip, 0x111)

#[a-zA-Z]* -> predefined operation
#[0-9]* -> temporary
$[a-zA-Z]* -> register or builtin
$[0-9]* -> argument

§[0-9]* -> label




		HIdList<Stack> stacks;
		HIdList<Memory> memories;
		//a list of all builtin functions that can not be represented with the ir
		HIdList<Builtin> builtins;
		HIdList<CallingConvention> callingconventions;


		//is filled at init
		HUniqueList<HId> instrIds;
		HIdMap<HId, InstrDefinition> instrdefs;
		//is filled at init with the instructions
		HSparseIdList<IRExpression> irExpressions;




$trap()

struct AsmBasicBlock {
	DynArray<Instruction> instructions;
	DynArray<ABBTarget> targets;
	bool unconditional_jump;
	u32 call_certainty;
	u32 return_certainty;
	u32 branch_certainty;
};
*/

#include "BitValue.h"
#include "ConstEval.h"

int main() {
	holodec::VMState state;
	holodec::BitValue lhs(127, 8);
	holodec::BitValue rhs(55, 8);
	holodec::BitValue res;

	holodec::bitfield_const_evaluator.multiply(&lhs, &rhs, &state, &res);
	lhs.print(stdout);
	fprintf(stdout, " + ");
	rhs.print(stdout);
	fprintf(stdout, " = ");
	res.print(stdout);
	fprintf(stdout, "\n");
	fprintf(stdout, "Size: %" PRId32 "\n", res.bitcount);
	if (state.carry) printf("Carry\n");
	if (state.overflow) printf("Overflow\n");
	if (state.underflow) printf("Underflow\n");
	return 0;


	holodec::parse_conf_file("../workingdir/avr.arch");
	return 0;
	ELFIO::elfio elf;
	if (!elf.load("fibseq.elf")) {
		printf("Cannot load Elf\n");
		return 0;
	}
	for (ELFIO::segment* segment : elf.segments) {
		printf("Index: 0x%" PRIx16 "\n", segment->get_index());
		printf("\tType: 0x%" PRIx32 "\n", segment->get_type());
		printf("\tflags: 0x%" PRIx32 "\n", segment->get_flags());
		printf("\talign: 0x%" PRIx64 "\n", segment->get_align());
		printf("\t0x%" PRIx64 "\n", segment->get_virtual_address());
		printf("\t0x%" PRIx64 "\n", segment->get_physical_address());
		printf("\tfile_size: 0x%" PRIx64 "\n", segment->get_file_size());
		printf("\tmemory_size: 0x%" PRIx64 "\n", segment->get_memory_size());
		printf("\toffset: 0x%" PRIx64 "\n", segment->get_offset());
	}
	for (ELFIO::section* section : elf.sections) {
		printf("Index: 0x%" PRIx16 "\n", section->get_index());
		printf("Name: %s\n", section->get_name().c_str());
		printf("\taddress: 0x%" PRIx64 "\n", section->get_address());
		printf("\tType: 0x%" PRIx32 "\n", section->get_type());
		printf("\tflags: 0x%" PRIx64 "\n", section->get_flags());
		printf("\tinfo: 0x%" PRIx32 "\n", section->get_info());
		printf("\tlink: 0x%" PRIx32 "\n", section->get_link());
		printf("\taddr_align: 0x%" PRIx64 "\n", section->get_addr_align());
		printf("\tentry_size: 0x%" PRIx64 "\n", section->get_entry_size());
		printf("\taddress: 0x%" PRIx64 "\n", section->get_address());
		printf("\tsize: 0x%" PRIx64 "\n", section->get_size());
		printf("\tname_string_offset: 0x%" PRIx32 "\n", section->get_name_string_offset());
		printf("\toffset: 0x%" PRIx64 "\n", section->get_offset());
	}
}
