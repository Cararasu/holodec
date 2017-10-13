#include "Hx86FunctionAnalyzer.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "HArchitecture.h"
#include "HString.h"
#include "HBinary.h"


#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

using namespace holodec;

HRegister* gh_x86_reg[X86_REG_ENDING] = {0,};
HRegister* gh_x86_reg_al;



void setJumpDest (HInstruction * instruction);
void setOperands (HInstruction * instruction, cs_x86 * x86info);


HRegister * getRegister (x86_reg reg) {
	if (reg >= X86_REG_ENDING)
		return 0;
	return gh_x86_reg[reg];
}

holox86::Hx86FunctionAnalyzer::Hx86FunctionAnalyzer (HArchitecture* arch) : holodec::HFunctionAnalyzer (arch) {}

holox86::Hx86FunctionAnalyzer::~Hx86FunctionAnalyzer() {}


bool holox86::Hx86FunctionAnalyzer::canAnalyze (HBinary* binary) {
	return holodec::caseCmpHString ("x86", binary->arch);
}
bool holox86::Hx86FunctionAnalyzer::init (HBinary* binary) {
	this->binary = binary;
	if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	if (cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		return false;
	return true;
}

bool holox86::Hx86FunctionAnalyzer::terminate() {
	this->binary = 0;
	cs_close (&handle);
	return true;
}

void analyzeInstruction (HInstruction* instr, size_t addr, cs_insn *insn);

bool holox86::Hx86FunctionAnalyzer::analyzeInsts (size_t addr) {
	cs_insn *insn;
	size_t count;

	size_t size = binary->getVDataSize (addr);
	size = size > 100 ? 100 : size;

	bool running = true;

	HInstruction instruction;
	do {
		prepareBuffer (addr);
		count = cs_disasm (handle, state.dataBuffer, state.bufferSize, addr, state.maxInstr, &insn);
		if (count > 0) {
			for (size_t i = 0; i < count; i++) {
				memset (&instruction, 0, sizeof (HInstruction));
				instruction.addr = insn[i].address;
				instruction.size = insn[i].size;
				setOperands (&instruction, insn[i].detail);

				switch (insn[i].detail->x86.prefix[0]) {
				case X86_PREFIX_REP:
					insn[i].id |= CUSOM_X86_INSTR_EXTR_REPE;
					break;
				case X86_PREFIX_REPNE:
					insn[i].id |= CUSOM_X86_INSTR_EXTR_REPNE;
					break;
				}

				instruction.instrdef = arch->getInstrDef (insn[i].id, insn[i].mnemonic);

				setJumpDest (&instruction);
				addr = insn[i].address + insn[i].size;
				if (!this->postInstruction (&instruction)) {
					running = false;
					break;
				}
			}

			cs_free (insn, count);
		} else {
			printf ("ERROR:: Failed to disassemble given code at address : 0x%x!\n", addr);
			running = false;
			return false;
		}
	} while (running);
	return true;
}



void holox86::Hx86FunctionAnalyzer::setOperands (HInstruction* instruction, cs_detail* csdetail) {

	cs_x86& x86 = csdetail->x86;

	for (uint8_t i = 0; i < x86.op_count; i++) {
		HIRArgument arg;
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf ("Invalid\n");
			break;
		case X86_OP_REG:{
			const char* regname = cs_reg_name (handle, x86.operands[i].reg);
			int index;
			int res = sscanf(regname,"st%d", &index);
			if(res == 1){
				arg = HIRArgument::createStck (arch->getStack ("st"),index);
			}else{
				arg = HIRArgument::createReg (arch->getRegister (regname));
			}
			break;
		}
		case X86_OP_IMM:
			arg = HIRArgument::createVal ( (uint64_t) x86.operands[i].imm, x86.operands[i].size * 8);
			break;
		case X86_OP_MEM: {
			uint64_t disp = 0;
			HRegister* baseReg;
			if(x86.operands[i].mem.segment == X86_REG_INVALID)
				x86.operands[i].mem.segment = X86_REG_CS;
			
			if (x86.operands[i].mem.base == X86_REG_RIP || x86.operands[i].mem.base == X86_REG_EIP) {
				arg = HIRArgument::createMemOp ( //HRegister* segment, HRegister* base, HRegister* index
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.segment)),//segment
						arch->getRegister (0),
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.index)),
						x86.operands[i].mem.scale, x86.operands[i].mem.disp + instruction->addr,
						x86.operands[i].size * 8
					);
			} else {
				arg = HIRArgument::createMemOp (
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.segment)),//segment
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.base)),//base
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.index)),//index
						x86.operands[i].mem.scale, x86.operands[i].mem.disp,
						x86.operands[i].size * 8
					);
			}
		}
		break;
		case X86_OP_FP:
			arg = HIRArgument::createVal ( (double) x86.operands[i].fp, x86.operands[i].size * 8);
			break;
		default:
			printf ("Invalid ...\n");
		}
		instruction->operands.push_back (arg);
	}
}

void holox86::Hx86FunctionAnalyzer::setJumpDest (HInstruction* instruction) {
	if (instruction->instrdef && instruction->instrdef->type == H_INSTR_TYPE_RET)
		return;

	instruction->nojumpdest = instruction->addr + instruction->size;
	if (instruction->instrdef){
		switch(instruction->instrdef->type){
		case H_INSTR_TYPE_JMP:
			instruction->nojumpdest = 0;
		case H_INSTR_TYPE_CJMP:
			if (instruction->operands[0].type == HIR_ARGTYPE_UINT)
				instruction->jumpdest = instruction->operands[0].uval;
			else if (instruction->operands[0].type == HIR_ARGTYPE_SINT)
				instruction->jumpdest = instruction->addr + instruction->operands[0].sval;
			break;
		default:
			instruction->jumpdest = 0;
			break;
		}
	}
}
