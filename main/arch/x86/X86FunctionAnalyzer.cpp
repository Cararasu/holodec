#include "X86FunctionAnalyzer.h"

#include "../../General.h"
#include <string.h>
#include "../../Architecture.h"
#include "../../HString.h"
#include "../../Binary.h"


#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

using namespace holodec;

Register* g_x86_reg[X86_REG_ENDING] = {0,};
Register* g_x86_reg_al;



void setJumpDest (Instruction * instruction);
void setOperands (Instruction * instruction, cs_x86 * x86info);


Register * getRegister (x86_reg reg) {
	if (reg >= X86_REG_ENDING)
		return 0;
	return g_x86_reg[reg];
}

holox86::X86FunctionAnalyzer::X86FunctionAnalyzer (Architecture* arch) : holodec::FunctionAnalyzer (arch) {}

holox86::X86FunctionAnalyzer::~X86FunctionAnalyzer() {}


bool holox86::X86FunctionAnalyzer::canAnalyze (Binary* binary) {
	return holodec::caseCmpHString ("x86", binary->arch.name);
}
bool holox86::X86FunctionAnalyzer::init (Binary* binary) {
	this->binary = binary;
	if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	if (cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		return false;
	return true;
}

bool holox86::X86FunctionAnalyzer::terminate() {
	this->binary = 0;
	cs_close (&handle);
	return true;
}

void analyzeInstruction (Instruction* instr, size_t addr, cs_insn *insn);

bool holox86::X86FunctionAnalyzer::analyzeInsts (size_t addr) {
	cs_insn *insn;
	size_t count;

	size_t size = binary->getVDataSize (addr);
	size = size > 100 ? 100 : size;

	bool running = true;

	Instruction instruction;
	do {
		prepareBuffer (addr);
		count = cs_disasm (handle, state.dataBuffer, state.bufferSize, addr, state.maxInstr, &insn);
		if (count > 0) {
			for (size_t i = 0; i < count; i++) {
				memset (&instruction, 0, sizeof (Instruction));
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
			printf ("ERROR:: Failed to disassemble given code at address : 0x%" PRIx64 "!\n", addr);
			running = false;
			return false;
		}
	} while (running);
	return true;
}



void holox86::X86FunctionAnalyzer::setOperands (Instruction* instruction, cs_detail* csdetail) {

	cs_x86& x86 = csdetail->x86;

	for (uint8_t i = 0; i < x86.op_count; i++) {
		IRArgument arg;
		switch (x86.operands[i].type) {
		case X86_OP_INVALID:
			printf ("Invalid\n");
			break;
		case X86_OP_REG:{
			const char* regname = cs_reg_name (handle, x86.operands[i].reg);
			uint32_t index;
			int res = sscanf_s(regname,"st%" SCNd32, &index);
			if(res == 1){
				arg = IRArgument::createStck (arch->getStack ("st"),index);
			}else{
				arg = IRArgument::createReg (arch->getRegister (regname));
			}
			break;
		}
		case X86_OP_IMM:
			arg = IRArgument::createUVal( (uint64_t) x86.operands[i].imm, x86.operands[i].size * 8);
			break;
		case X86_OP_MEM: {
			/*
			if(x86.operands[i].mem.segment == X86_REG_INVALID)
				x86.operands[i].mem.segment = X86_REG_CS;
			*/
			if (x86.operands[i].mem.base == X86_REG_RIP || x86.operands[i].mem.base == X86_REG_EIP) {
				arg = IRArgument::createMemOp ( //Register* segment, Register* base, Register* index
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.segment)),//segment
						arch->getRegister ((HId)0),
						arch->getRegister (cs_reg_name (handle, x86.operands[i].mem.index)),
						x86.operands[i].mem.scale, x86.operands[i].mem.disp + instruction->addr + instruction->size,
						x86.operands[i].size * 8
					);
			} else {
				arg = IRArgument::createMemOp (
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
			arg = IRArgument::createDVal ( (double) x86.operands[i].fp, x86.operands[i].size * 8);
			break;
		default:
			printf ("Invalid ...\n");
		}
		instruction->operands.push_back (arg);
	}
}

void holox86::X86FunctionAnalyzer::setJumpDest (Instruction* instruction) {
	if (instruction->instrdef && instruction->instrdef->type == InstructionType::eRet)
		return;
	/*
	instruction->nojumpdest = instruction->addr + instruction->size;
	if (instruction->instrdef){
		switch(instruction->instrdef->type){
		case InstructionType::eJmp:
			instruction->nojumpdest = 0;
		case InstructionType::eCJmp:
			if (instruction->operands[0].type == IR_ARGTYPE_UINT)
				instruction->jumpdest = instruction->operands[0].uval;
			else if (instruction->operands[0].type == IR_ARGTYPE_SINT)
				instruction->jumpdest = instruction->addr + instruction->operands[0].sval;
			break;
		default:
			instruction->jumpdest = 0;
			break;
		}
	}*/
}
