#ifndef H_FUNCTION_H
#define H_FUNCTION_H

#include "General.h"
#include "Section.h"
#include "InstrDefinition.h"

#include "Argument.h"



#define HINSTRUCTION_MAX_OPERANDS (4)

namespace holodec {

	struct Instruction {
		uint64_t addr;
		uint64_t size;
		InstrDefinition* instrdef;

		uint64_t nojumpdest = 0;//fall through dst
		uint64_t jumpdest = 0;//if condition is true
		uint64_t calldest = 0;//if call succeeds -> creates new function symbol

		HLocalBackedList<IRArgument,HINSTRUCTION_MAX_OPERANDS> operands;

		void print (Architecture* arch, int indent = 0);
	};
	struct HJumpTable {
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
				printf ("0x%X", entry.addr);
			}
		}
	};
	struct HBasicBlock {
		HId id;
		HList<Instruction> instructions;
		HId nextblock;
		HId nextcondblock;

		HId jumptable;

		uint64_t addr;
		uint64_t size;

		void print (Architecture* arch, int indent = 0) {
			printIndent (indent);
			printf ("BB 0x%x-0x%x t:0x%x f:0x%x\n", addr, addr + size, instructions.back().jumpdest, instructions.back().nojumpdest);
			for (Instruction& instruction : instructions) {
				instruction.print (arch, indent + 1);
			}
		}
	};
	struct Function {
		HId id;
		HId symbolref;
		HId callingconvention;
		uint64_t baseaddr;
		HIdList<HBasicBlock> basicblocks;
		HIdList<HJumpTable> jumptables;
		VisibilityType* visibility;
		SSARepresentation ssaRep;

		HList<uint64_t> addrToAnalyze;
		
		HBasicBlock* findBasicBlock (size_t addr) {
			if (addr) {
				for (HBasicBlock& bb : basicblocks) {
					if (bb.addr == addr)
						return &bb;
				}
			}
			return nullptr;
		}
		HBasicBlock* findBasicBlockDeep (size_t addr) {
			if (addr) {
				for (HBasicBlock& bb : basicblocks) {
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

		HId addBasicBlock (HBasicBlock basicblock) {
			return basicblocks.push_back (basicblock);
		}
		void clear() {
			id = 0;
			symbolref = 0;
			basicblocks.clear();
			ssaRep.clear();
			visibility = 0;
		}

		void print (Architecture* arch, int indent = 0) {
			printIndent (indent);
			printf ("Printing Function\n");
			for (HBasicBlock& bb : basicblocks) {
				bb.print (arch, indent + 1);
			}
			
			ssaRep.print(arch, indent + 1);
		}
	};

}

#endif // H_FUNCTION_H
