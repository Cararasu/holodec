
#include "pch.h"
#include <iostream>

#include "String.h"
#include "Array.h"
#include "Parser.h"
#include <elfio/elfio.hpp>


/*


DataSegment
	DataSource, offset
	Patches

MappedData -> DataSegment -> DataSource


Architecture identification: Type-String, base-bit-size
	endianess

	default compiler-profile


Function
	id
	name
	description

	signature -> some datatype

	referenced stacks -> some datatype

	conservative SSA-From
	aggressive SSA-From
	conservative AST
	aggressive AST



TODO change registers to register file implementation

registerfile
	...

	explicit-writes -> every write is displayed as a write of that register
	explicit-reads -> every read is displayed as a read of that register

	implicit-writes -> no write is displayed
	implicit-reads -> no read is displayed

	volatile -> reads or writes can not be optimized away

	general registers -> -

	debug registers -> explicit-writes, explicit-reads, volatile
	segment registers -> explicit-writes, implicit-reads, volatile
	flag registar -> implicit-writes, explicit-reads

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
layer 3.3:
	conservative optimization passes
layer 3.5:
	SSA-copy
layer 3.7:
	aggressive optimization passes
layer 4:
	AST-generation
layer 4.5:
	AST-optimization
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

#include "Binary.h"
#include "BitValue.h"
#include "ConstEval.h"


void setOperands(csh handle, cs_detail* csdetail) {

	cs_x86& x86 = csdetail->x86;

	for (uint8_t i = 0; i < x86.op_count; i++) {
		printf("\tArgument ");
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf("Invalid");
			break;
		case X86_OP_REG: {
			const char* regname = cs_reg_name(handle, x86.operands[i].reg);
			printf("Register %s Bytes: %" PRId32, regname, x86.operands[i].size);
			uint32_t index;
			int res = sscanf_s(regname, "st%" SCNd32, &index);
			if (res == 1) {
				//arg = IRArgument::createStck(arch->getStack("st"), index);
			}
			else {
				//arg = IRArgument::createReg(arch->getRegister(regname));
			}
			break;
		}
		case X86_OP_IMM:
			printf("Value: %" PRIx64 " Bytes: %" PRId32, (uint64_t)x86.operands[i].imm, x86.operands[i].size);
			//arg = IRArgument::createUVal((uint64_t)x86.operands[i].imm, x86.operands[i].size * arch->bitbase);
			break;
		case X86_OP_MEM: {
			/*
			if(x86.operands[i].mem.segment == X86_REG_INVALID)
				x86.operands[i].mem.segment = X86_REG_CS;
			*/
			const char* segreg = cs_reg_name(handle, x86.operands[i].mem.segment);
			const char* basereg = cs_reg_name(handle, x86.operands[i].mem.base);
			const char* indexreg = cs_reg_name(handle, x86.operands[i].mem.index);
			printf("%s:[%s + 0x%x*%s + %" PRId64"] Bytes: %" PRId32, 
				segreg, 
				basereg,
				x86.operands[i].mem.scale, 
				indexreg, 
				x86.operands[i].mem.disp, 
				x86.operands[i].size);
			if (x86.operands[i].mem.base == X86_REG_RIP || x86.operands[i].mem.base == X86_REG_EIP) {
				/*arg = IRArgument::createMemOp( //Register* segment, Register* base, Register* index
					arch->getRegister(cs_reg_name(handle, x86.operands[i].mem.segment)),//segment
					arch->getRegister((HId)0),
					arch->getRegister(cs_reg_name(handle, x86.operands[i].mem.index)),
					x86.operands[i].mem.scale, x86.operands[i].mem.disp + instruction->addr + instruction->size,
					x86.operands[i].size * arch->bitbase
				);*/
			}
			else {
				/*arg = IRArgument::createMemOp(
					arch->getRegister(cs_reg_name(handle, x86.operands[i].mem.segment)),//segment
					arch->getRegister(cs_reg_name(handle, x86.operands[i].mem.base)),//base
					arch->getRegister(cs_reg_name(handle, x86.operands[i].mem.index)),//index
					x86.operands[i].mem.scale, x86.operands[i].mem.disp,
					x86.operands[i].size * arch->bitbase
				);*/
			}
		}
						 break;
		case X86_OP_FP:
			//arg = IRArgument::createFVal((double)x86.operands[i].fp, x86.operands[i].size * arch->bitbase);
			break;
		default:
			printf("Invalid ...");
		}
		printf("\n");
	}
}
#include <streambuf>
#include <istream>
#include "DataSource.h"

struct membuf : std::streambuf
{
	membuf(char *begin, char *end) : begin(begin), end(end)
	{
		this->setg(begin, begin, end);
	}

	virtual pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::in) override
	{
		if (dir == std::ios_base::cur)
			gbump(off);
		else if (dir == std::ios_base::end)
			setg(begin, end + off, end);
		else if (dir == std::ios_base::beg)
			setg(begin, begin + off, end);

		return gptr() - eback();
	}

	virtual pos_type seekpos(std::streampos pos, std::ios_base::openmode mode) override
	{
		return seekoff(pos - pos_type(off_type(0)), std::ios_base::beg, mode);
	}

	char *begin, *end;
};
int main() {


	holodec::parse_conf_file("../workingdir/avr.arch");
	printf("----------\n");
	holodec::parse_conf_file("../workingdir/x86.arch");
	//holodec::parse_conf_file("../workingdir/x86_64.arch");

	holodec::Binary* binary = new holodec::Binary();
	holodec::MemorySpace memoryspace;
	memoryspace.name = "mem";
	memoryspace.wordsize = 1;
	memoryspace.endianess = holodec::Endianess::eLittle;
	binary->memorySpaces.insert(memoryspace);
	{
		holodec::DataSource source;
		if (!holodec::load_file("../workingdir/fibseq32", &source)) {
			printf("Could not open File\n");
			return -1;
		}

		membuf stream((char*)source.m_data, (char*)source.m_data + source.m_size);
		std::istream istream(&stream);
		ELFIO::elfio elf;
		if (!elf.load(istream)) {
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

			if (section->get_flags() & 0x4) {
				csh handle;
				if (elf.get_class() == ELFCLASS32) {
					if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
						return false;
				}
				else {
					if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
						return false;
				}
				if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
					return false;
				cs_insn *instr = cs_malloc(handle);

				const uint8_t* data = (const uint8_t*)section->get_data();
				size_t size = section->get_size();
				uint64_t address = section->get_address();

				while (size > 0) {
					while (cs_disasm_iter(handle, &data, &size, &address, instr)) {
						printf("0x%" PRIx64 ":\t%s\t\t%s\n", instr->address, instr->mnemonic, instr->op_str);
						setOperands(handle, instr->detail);
					}
					if (size > 0) {
						printf("Skipped byte 0x%x\n", *data);
						data++;
						address++;
						size--;
					}
				}
				cs_free(instr, 1);
				cs_close(&handle);
			}
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
}
