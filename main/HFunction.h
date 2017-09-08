#ifndef H_FUNCTION_H
#define H_FUNCTION_H

#include "HGeneral.h"
#include "HSection.h"
#include "HInstrDefinition.h"
#include "HId.h"
#include "HArgument.h"



#define HINSTRUCTION_MAX_OPERANDS (4)

namespace holodec {

	struct HInstruction {
		size_t addr;
		size_t size;
		HInstrDefinition* instrdef;

		HInstructionCondition condition;

		size_t nojumpdest;//fall through dst
		size_t jumpdest;//if condition is true
		size_t calldest;//if call succeeds -> creates new function symbol

		HLocalBackedList<HArgument,HINSTRUCTION_MAX_OPERANDS> operands;

		void print (HArchitecture* arch, int indent = 0);
	};
	struct HJumpTable {
		struct HEntry {
			size_t addr;//where the entry is in memory
			size_t targetaddr;//the target of the jump
			HId bb_id;
		};

		HId id;
		size_t addr;
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
		HList<HInstruction> instructions;
		HId nextblock;
		HId nextcondblock;

		HId jumptable;

		HInstructionCondition cond;
		size_t addr;
		size_t size;

		void print (HArchitecture* arch, int indent = 0) {
			printIndent (indent);
			printf ("BB 0x%x-0x%x t:0x%x f:0x%x\n", addr, addr + size, instructions.back().jumpdest, instructions.back().nojumpdest);
			for (HInstruction& instruction : instructions) {
				instruction.print (arch, indent + 1);
			}
		}
	};
	struct HFunction {
		HId id;
		HId symbolref;
		HIdGenerator gen_bb;
		HIdGenerator gen_jt;
		HList<HBasicBlock> basicblocks;
		HList<HJumpTable> jumptables;
		HVisibilityType* visibility;

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
						for (HInstruction& instr : bb.instructions) {
							if (instr.addr == addr)
								return &bb;
						}
					}
				}
			}
			return nullptr;
		}

		HId addBasicBlock (HBasicBlock basicblock) {
			basicblock.id = gen_bb.next();
			basicblocks.push_back (basicblock);
			return basicblock.id;
		}
		void clear() {
			id = 0;
			symbolref = 0;
			gen_bb.clear();
			basicblocks.clear();
			visibility = 0;
		}

		void print (HArchitecture* arch, int indent = 0) {
			printIndent (indent);
			printf ("Printing Function\n");
			for (HBasicBlock& bb : basicblocks) {
				bb.print (arch, indent + 1);
			}
		}
	};

}

#endif // H_FUNCTION_H
