#include "Rx86FunctionAnalyzer.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "RArchitecture.h"
#include "RString.h"


#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

using namespace holodec;

RRegister* gr_x86_reg[X86_REG_ENDING] = {0,};
RRegister* gr_x86_reg_al;



void setJumpDest (RInstruction * instruction);
void setOperands (RInstruction * instruction, cs_x86 * x86info);


RRegister * getRegister (x86_reg reg) {
	if (reg >= X86_REG_ENDING)
		return 0;
	return gr_x86_reg[reg];
}

holox86::Rx86FunctionAnalyzer::Rx86FunctionAnalyzer (RArchitecture* arch) : holodec::RFunctionAnalyzer (arch) {}

holox86::Rx86FunctionAnalyzer::~Rx86FunctionAnalyzer() {}


bool holox86::Rx86FunctionAnalyzer::canAnalyze (RBinary* binary) {
	return holodec::caseCmpRString ("x86", binary->arch);
}
bool holox86::Rx86FunctionAnalyzer::init (RBinary* binary) {
	this->binary = binary;
	if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	if (cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		return false;
	return true;
}

bool holox86::Rx86FunctionAnalyzer::terminate() {
	this->binary = 0;
	cs_close (&handle);
	return true;
}

void analyzeInstruction (RInstruction* instr, size_t addr, cs_insn *insn);

void holox86::Rx86FunctionAnalyzer::analyzeInsts (size_t addr, size_t max_count) {
	cs_insn *insn;
	size_t count;

	size_t size = binary->getVDataSize (addr);
	size = size > 100 ? 100 : size;

	RInstruction instruction;
	do {
		count = cs_disasm (handle, binary->getVDataPtr (addr), size, addr, 1, &insn);
		if (count > 0) {

			memset (&instruction, 0, sizeof (RInstruction));

			analyzeInstruction (&instruction, addr, insn);
			addr += insn->size;

			cs_free (insn, count);
		} else
			printf ("ERROR: Failed to disassemble given code!\n");
	} while (this->postInstruction (&instruction));
}


void holox86::Rx86FunctionAnalyzer::analyzeInstruction (RInstruction* instr, size_t addr, cs_insn *insn) {
	RInstruction& instruction = *instr;
	instruction.addr = addr;

	setOperands (instr, insn->detail);

	instruction.size = insn->size;

	switch (insn->bytes[0]) {
	case 0x6B:
		instruction.instrdef = holox86::x86architecture.getInstrDef ("imul_signed");
		break;
	case 0x0F: {
		switch (insn->bytes[1]) {
		case 0xAD:
			instruction.instrdef = holox86::x86architecture.getInstrDef ("shrd_cl");
			break;
		default:
			instruction.instrdef = holox86::x86architecture.getInstrDef (insn->mnemonic);
		}
	}
	break;
	//TODO make it available to parser prefix 0x6B
	case 0xD2:
	case 0xD3: {
		char buffer[16];
		snprintf (buffer, 16, "%s_cl", insn->mnemonic);
		instruction.instrdef = holox86::x86architecture.getInstrDef (buffer);
	}
	break;

	//sar,shr,sal,shl
	default: {
		RStringMap<RInstrDefinition> instrdefs;
		instruction.instrdef = holox86::x86architecture.getInstrDef (insn->mnemonic);
	}
	break;
	}
	setJumpDest (&instruction);

}

void holox86::Rx86FunctionAnalyzer::setOperands (RInstruction* instruction, cs_detail* csdetail) {

	for(uint8_t i = 0; i < csdetail->regs_read_count;i++){
		//printf("Read: %s\n",cs_reg_name (handle,csdetail->regs_read[i]));
	}
	for(uint8_t i = 0; i < csdetail->regs_write_count;i++){
		//printf("Write: %s\n",cs_reg_name (handle,csdetail->regs_write[i]));
	}
	
	cs_x86& x86 = csdetail->x86;
	instruction->opcount = x86.op_count;
	
	for (uint8_t i = 0; i < x86.op_count; i++) {
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf ("Invalid\n");
			break;
		case X86_OP_REG:
			instruction->operands[i].type = {R_LOCAL_TYPE_REGISTER, x86.operands[i].size, 0};
			instruction->operands[i].reg = holox86::x86architecture.getRegister (cs_reg_name (handle, x86.operands[i].reg));
			if (instruction->operands[i].reg)
				;//printf ("Reg: %s", instruction->operands[i].reg->name);
			break;
		case X86_OP_IMM:
			instruction->operands[i].type = {R_LOCAL_TYPE_IMM_UNSIGNED, x86.operands[i].size, 0};
			instruction->operands[i].ival = x86.operands[i].imm;
			//printf ("Imm: %d", instruction->operands[i].ival);
			break;
		case X86_OP_MEM:
			instruction->operands[i].type = {R_LOCAL_TYPE_MEM, x86.operands[i].size, 0};
			instruction->operands[i].mem.base = holox86::x86architecture.getRegister (cs_reg_name (handle, x86.operands[i].mem.base));
			instruction->operands[i].mem.disp = x86.operands[i].mem.disp;
			instruction->operands[i].mem.index = holox86::x86architecture.getRegister (cs_reg_name (handle, x86.operands[i].mem.index));
			instruction->operands[i].mem.scale = x86.operands[i].mem.scale;

			//printf ("[%s + %s*%d + %d]", instruction->operands[i].mem.base ? instruction->operands[i].mem.base->name : "-",
			//        instruction->operands[i].mem.index ? instruction->operands[i].mem.index->name : "-",
			//        instruction->operands[i].mem.scale, instruction->operands[i].mem.disp);
			break;
		case X86_OP_FP:
			instruction->operands[i].type = {R_LOCAL_TYPE_IMM_FLOAT, x86.operands[i].size, 0};
			instruction->operands[i].fval = x86.operands[i].fp;
			//printf ("F: %f", instruction->operands[i].fval);
			break;
		default:
			printf ("Invalid ...\n");
		}
		//TODO add implicit reg access
		//printf (" -- ");
	}
	//printf ("\n");
}

void holox86::Rx86FunctionAnalyzer::setJumpDest (RInstruction* instruction) {

	if (instruction->instrdef && (instruction->instrdef->type == R_INSTR_TYPE_JMP || instruction->instrdef->type2 == R_INSTR_TYPE_JMP)) {
		if (instruction->operands[0].type.type == R_LOCAL_TYPE_IMM_UNSIGNED)
			instruction->jumpdest = instruction->operands[0].ival;
		else if (instruction->operands[0].type.type == R_LOCAL_TYPE_IMM_SIGNED)
			instruction->jumpdest = instruction->addr + (int64_t) instruction->operands[0].ival;
	}
	instruction->nojumpdest = instruction->addr + instruction->size;
}
