#ifndef H_FUNCTION_H
#define H_FUNCTION_H

#include "HGeneral.h"
#include "HSection.h"
#include "HInstrDefinition.h"
#include "HId.h"



#define HINSTRUCTION_MAX_OPERANDS (4)

namespace holodec {

	enum HLocalType {
		H_LOCAL_TYPE_REGISTER = 1,
		H_LOCAL_TYPE_STACK,
		H_LOCAL_TYPE_MEM,
		H_LOCAL_TYPE_IMM_SIGNED,
		H_LOCAL_TYPE_IMM_UNSIGNED,
		H_LOCAL_TYPE_IMM_FLOAT,
	};
	enum HOpAccess {
		H_OP_ACCESS_READ = 1,
		H_OP_ACCESS_WRITE = 2,
		H_OP_ACCESS_RW = 3,
	};

	struct HInstArgType {
		HLocalType type;//(reg or stack or signed or unsigned)
		//size / minimal machineword size
		//e.g.
		//1 -> 8 bit
		//2 -> 16 bit
		//4 -> 32 bit
		//8 -> 64 bit
		//16 -> 128 bit
		//32 -> 256 bit
		//64 -> 512 bit
		uint16_t size;
		uint32_t flags;//is memoperand, functionptr,...
	};

	typedef int64_t HArgIntImmediate;
	typedef double HArgFloatImmediate;
	typedef uint64_t HArgStack;
	struct HArgMem { //segment::[base + index*scale + disp]
		HId segment;
		HId base;
		HId index;
		HArgIntImmediate scale;
		HArgIntImmediate disp;
	};
	struct HInstArgument {
		union { //ordered first because of tighter memory layout
			HArgIntImmediate ival;
			HArgFloatImmediate fval;
			HArgMem mem;
			HId reg;
			HId stackindex;
		};
		HInstArgType type;// size || memoperand || (reg or stack or signed or unsigned)

		void print (HArchitecture* arch);
	};
	struct HInstruction {
		size_t addr;
		size_t size;
		HInstrDefinition* instrdef;

		HInstructionCondition condition;

		size_t nojumpdest;//fall through dst
		size_t jumpdest;//if condition is true
		size_t calldest;//if call succeeds -> creates new function symbol

		size_t opcount;
		HInstArgument operands[HINSTRUCTION_MAX_OPERANDS];

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
