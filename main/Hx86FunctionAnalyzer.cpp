#include "Hx86FunctionAnalyzer.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "HArchitecture.h"
#include "HString.h"


#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

using namespace holodec;

HRegister* gr_x86_reg[X86_REG_ENDING] = {0,};
HRegister* gr_x86_reg_al;



void setJumpDest (HInstruction * instruction);
void setOperands (HInstruction * instruction, cs_x86 * x86info);


HRegister * getRegister (x86_reg reg) {
	if (reg >= X86_REG_ENDING)
		return 0;
	return gr_x86_reg[reg];
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

	bool running;

	HInstruction instruction;
	do {
		prepareBuffer (addr);
		count = cs_disasm (handle, state.dataBuffer, state.bufferSize, addr, state.maxInstr, &insn);
		if (count > 0) {

			for (size_t i = 0; i < count; i++) {
				memset (&instruction, 0, sizeof (HInstruction));
				instruction.addr = addr;
				instruction.size = insn[i].size;
				setOperands (&instruction, insn[i].detail);
				
				switch (insn[i].bytes[0]) {
				case 0x6B:
					instruction.instrdef = arch->getInstrDef ("imul_signed");
					break;
				case 0x0F: {
					switch (insn[i].bytes[1]) {
					case 0xAD:
						instruction.instrdef = arch->getInstrDef ("shrd_cl");
						break;
					default:
						instruction.instrdef = arch->getInstrDef (insn[i].mnemonic);
					}
				}
				break;
				//TODO make it available to parser prefix 0x6B
				case 0xD2:
				case 0xD3: {
					char buffer[16];
					snprintf (buffer, 16, "%s_cl", insn[i].mnemonic);
					instruction.instrdef = arch->getInstrDef (buffer);
				}
				break;
				//sar,shr,sal,shl
				default:
					instruction.instrdef = arch->getInstrDef (insn[i].mnemonic);
					break;
				}
				setJumpDest (&instruction);
				addr += insn[i].size;
				if (!this->postInstruction (&instruction)){
					running = false;
					break;
				}
			}

			cs_free (insn, count);
		} else {
			printf ("ERROR:: Failed to disassemble given code!\n");
			running = false;
		}
	} while (running);
	
}



void holox86::Hx86FunctionAnalyzer::setOperands (HInstruction* instruction, cs_detail* csdetail) {

	cs_x86& x86 = csdetail->x86;
	instruction->opcount = x86.op_count;

	for (uint8_t i = 0; i < x86.op_count; i++) {
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf ("Invalid\n");
			break;
		case X86_OP_REG:
			instruction->operands[i].type = {H_LOCAL_TYPE_REGISTER, x86.operands[i].size, 0};
			instruction->operands[i].reg = arch->getRegister (cs_reg_name (handle, x86.operands[i].reg));
			break;
		case X86_OP_IMM:
			instruction->operands[i].type = {H_LOCAL_TYPE_IMM_UNSIGNED, x86.operands[i].size, 0};
			instruction->operands[i].ival = x86.operands[i].imm;
			break;
		case X86_OP_MEM:
			instruction->operands[i].type = {H_LOCAL_TYPE_MEM, x86.operands[i].size, 0};
			instruction->operands[i].mem.segment = arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.segment));
			if(x86.operands[i].mem.base == X86_REG_RIP || x86.operands[i].mem.base == X86_REG_EIP){
				x86.operands[i].mem.disp += instruction->addr;
				instruction->operands[i].mem.base = 0;
			}else{
				instruction->operands[i].mem.base = arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.base));
			}
			instruction->operands[i].mem.disp = x86.operands[i].mem.disp;
			instruction->operands[i].mem.index = arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.index));
			instruction->operands[i].mem.scale = x86.operands[i].mem.scale;

			break;
		case X86_OP_FP:
			instruction->operands[i].type = {H_LOCAL_TYPE_IMM_FLOAT, x86.operands[i].size, 0};
			instruction->operands[i].fval = x86.operands[i].fp;
			break;
		default:
			printf ("Invalid ...\n");
		}
	}
}

void holox86::Hx86FunctionAnalyzer::setJumpDest (HInstruction* instruction) {

	if (instruction->instrdef && (instruction->instrdef->type == H_INSTR_TYPE_JMP || instruction->instrdef->type2 == H_INSTR_TYPE_JMP)) {
		if (instruction->operands[0].type.type == H_LOCAL_TYPE_IMM_UNSIGNED)
			instruction->jumpdest = instruction->operands[0].ival;
		else if (instruction->operands[0].type.type == H_LOCAL_TYPE_IMM_SIGNED)
			instruction->jumpdest = instruction->addr + (int64_t) instruction->operands[0].ival;
	}
	instruction->nojumpdest = instruction->addr + instruction->size;
}
