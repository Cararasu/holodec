
#include "pch.h"
#include <iostream>

#include "String.h"
#include "Array.h"
#include "Parser.h"
#include <elfio/elfio.hpp>


/*

hmm change registers to register file implementation

registerfile
	...
	volatile
	register
		...

memoryspace
	

layer 0:
	file parser

	File -> FileParser -> Binary
layer 1:
	linear sweep + recursive basic block disassembler
	and address queue
	Datastructure
		basic blocks
		types
		locations
	controlled by IR-translation but does not create IR

	Binary -> BasicBlockAnalyser -> BasicBlocks
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

$rip = 0x111

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
	holodec::StaticDynArray<holodec::u64, 12> arr;

	for (holodec::u64 i = 0; i < 100; i++) {
		arr.push_back(i);
	}

	for (holodec::u64 i : arr) {
		printf("%" PRIu64 "\n", i);
	}
	holodec::parse_conf_file("../workingdir/avr.arch");



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

		// Check section type
		if (section->get_type() == SHT_SYMTAB) {
			const ELFIO::symbol_section_accessor symbols(elf, section);
			for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
				std::string   name;
				ELFIO::Elf64_Addr    value;
				ELFIO::Elf_Xword     size;
				unsigned char bind;
				unsigned char type;
				ELFIO::Elf_Half      section_index;
				unsigned char other;

				// Read symbol properties
				symbols.get_symbol(j, name, value, size, bind,
					type, section_index, other);
				std::cout << j << " " << name << " " << value << std::endl;
			}
		}
	}

	if (elf.get_class() == ELFCLASS32)
		std::cout << "ELF32" << std::endl;
	else
		std::cout << "ELF64" << std::endl;
	if (elf.get_encoding() == ELFDATA2LSB)
		std::cout << "Little endian" << std::endl;
	else
		std::cout << "Big endian" << std::endl;

}
