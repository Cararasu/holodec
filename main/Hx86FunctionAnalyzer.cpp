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

void holox86::Hx86FunctionAnalyzer::analyzeInsts (size_t addr) {
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
				if (!instruction.instrdef)
					printf ("ID: %d\n", insn[i].id);

				setJumpDest (&instruction);
				addr = insn[i].address + insn[i].size;
				if (!this->postInstruction (&instruction)) {
					running = false;
					break;
				}
			}

			cs_free (insn, count);
		} else {
			printf ("ERROR:: Failed to disassemble given code at address : 0x%x!\n",addr);
			running = false;
		}
	} while (running);

}



void holox86::Hx86FunctionAnalyzer::setOperands (HInstruction* instruction, cs_detail* csdetail) {

	cs_x86& x86 = csdetail->x86;

	for (uint8_t i = 0; i < x86.op_count; i++) {
		HInstArgument arg;
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf ("Invalid\n");
			break;
		case X86_OP_REG:
			arg.type = H_LOCAL_TYPE_REGISTER;
			arg.reg = arch->getRegister (cs_reg_name (handle, x86.operands[i].reg))->id;
			break;
		case X86_OP_IMM:
			arg.type = H_LOCAL_TYPE_IMM_UNSIGNED;
			arg.ival = x86.operands[i].imm;
			break;
		case X86_OP_MEM:
			arg.type = H_LOCAL_TYPE_MEM;
			arg.mem.segment = arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.segment))->id;
			if (x86.operands[i].mem.base == X86_REG_RIP || x86.operands[i].mem.base == X86_REG_EIP) {
				x86.operands[i].mem.disp += instruction->addr;
				arg.mem.base = 0;
			} else {
				arg.mem.base = arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.base))->id;
			}
			arg.mem.disp = x86.operands[i].mem.disp;
			arg.mem.index = arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.index))->id;
			arg.mem.scale = x86.operands[i].mem.scale;

			break;
		case X86_OP_FP:
			arg.type = H_LOCAL_TYPE_IMM_FLOAT;
			arg.fval = x86.operands[i].fp;
			break;
		default:
			printf ("Invalid ...\n");
		}
		arg.size = x86.operands[i].size * 8;
		instruction->operands.add(arg);
	}
}

void holox86::Hx86FunctionAnalyzer::setJumpDest (HInstruction* instruction) {
	if (instruction->instrdef && instruction->instrdef->type == H_INSTR_TYPE_RET && instruction->instrdef->condition == H_INSTR_COND_TRUE)
		return;

	instruction->nojumpdest = instruction->addr + instruction->size;
	if (instruction->instrdef && (instruction->instrdef->type == H_INSTR_TYPE_JMP || instruction->instrdef->type2 == H_INSTR_TYPE_JMP)) {
		if (instruction->condition == H_INSTR_COND_TRUE && instruction->instrdef->condition == H_INSTR_COND_TRUE) {
			instruction->nojumpdest = 0;
		}
		if (instruction->operands[0].type == H_LOCAL_TYPE_IMM_UNSIGNED)
			instruction->jumpdest = instruction->operands[0].ival;
		else if (instruction->operands[0].type == H_LOCAL_TYPE_IMM_SIGNED)
			instruction->jumpdest = instruction->addr + (int64_t) instruction->operands[0].ival;
	}
}
