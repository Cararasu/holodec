#ifndef H_FUNCTION_H
#define H_FUNCTION_H

#include "General.h"
#include "Section.h"
#include "InstrDefinition.h"

#include "Argument.h"



#define HINSTRUCTION_MAX_OPERANDS (4)

namespace holodec {

	struct Instruction {
		uint64_t addr = 0;
		uint32_t size = 0;
		InstrDefinition* instrdef;

		uint64_t nojumpdest = 0;//fall through dst
		uint64_t jumpdest = 0;//if condition is true

		HLocalBackedList<IRArgument,HINSTRUCTION_MAX_OPERANDS> operands;

		void print (Architecture* arch, int indent = 0);
	};
	struct JumpTable {
		struct HEntry {
			uint64_t addr;//where the entry is in memory
			uint64_t targetaddr;//the target of the jump
			HId bb_id;
		};

		HId id;
		uint64_t addr;
		HList<HEntry> entries;

		void print (int indent = 0) {
			printIndent (indent);
			printf ("JumpTable \n");
			for (HEntry& entry : entries) {
				printIndent (indent + 1);
				printf ("0x%" PRIX64, entry.addr);
			}
		}
	};
	struct DisAsmBasicBlock {
		HId id;
		HList<Instruction> instructions;
		HId nextblock;
		HId nextcondblock;

		HId jumptable;

		uint64_t addr;
		uint32_t size;

		void print (Architecture* arch, int indent = 0) {
			printIndent (indent);
			printf ("BB 0x%" PRIx64 "-0x%" PRIx64 " t:0x%" PRIx64 " f:0x%" PRIx64 "\n", addr, addr + size, instructions.back().jumpdest, instructions.back().nojumpdest);
			for (Instruction& instruction : instructions) {
				instruction.print (arch, indent + 1);
			}
		}
	};
	// Unknown -> FunctionRead
	enum class RegisterUsedFlag{
		eNone	= 0x0,
		eWrite	= 0x1,
		eRead	= 0x2,
		eArithmeticChange = 0x4,
	};
	struct RegisterState{
		HId regId;
		Flags<RegisterUsedFlag> flags;
		int64_t arithChange = 0;
	};
	struct FuncRegState {
		HList<RegisterState> states;
		bool parsed = false;

		RegisterState* getRegisterState(HId regId) {

			for (RegisterState& regState : states) {
				if (regState.regId == regId)
					return &regState;
			}
			return nullptr;
		}
		RegisterState* getNewRegisterState(HId regId) {

			for (RegisterState& regState : states) {
				if (regState.regId == regId)
					return &regState;
			}
			states.push_back({ regId, {}, 0 });
			return &states.back();
		}
	};
	
	struct Function {
		HId id;
		HId symbolref;
		uint64_t baseaddr;
		
		FuncRegState regStates;
		HUniqueList<uint64_t> funcsCalled;
		HList<uint64_t> funcsCall;
		
		HIdList<DisAsmBasicBlock> basicblocks;
		HIdList<JumpTable> jumptables;
		SSARepresentation ssaRep;

		HSet<uint64_t> addrToAnalyze;
		
		DisAsmBasicBlock* findBasicBlock (size_t addr) {
			if (addr) {
				for (DisAsmBasicBlock& bb : basicblocks) {
					if (bb.addr == addr)
						return &bb;
				}
			}
			return nullptr;
		}
		DisAsmBasicBlock* findBasicBlockDeep (size_t addr) {
			if (addr) {
				for (DisAsmBasicBlock& bb : basicblocks) {
					if (bb.addr == addr)
						return &bb;
					if (bb.addr <= addr && addr < (bb.addr + bb.size)) {
						for (Instruction& instr : bb.instructions) {
							if (instr.addr == addr)
								return &bb;
						}
					}
				}
			}
			return nullptr;
		}

		HId addBasicBlock (DisAsmBasicBlock basicblock) {
			return basicblocks.push_back (basicblock);
		}

		void clear() {
			id = 0;
			symbolref = 0;
			basicblocks.clear();
			ssaRep.clear();
		}

		void print(Architecture* arch, int indent = 0);
	};

}

#endif // H_FUNCTION_H
