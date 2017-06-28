#ifndef H_FUNCTION_H
#define H_FUNCTION_H

#include "HGeneral.h"
#include "HSection.h"
#include "HInstrDefinition.h"
#include "HIdGenerator.h"

namespace holodec {



#define H_SET_FLAG(val,flag) val |= flag
#define H_SET_FLAGM(val,flag,mask) val = (val & ~mask) | flag

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
	struct HRegister {
		HString name;
		size_t size;
		size_t offset;
		HList<HRegister> subregisters;

		HRegister() = default;
		HRegister (HString name, size_t size, size_t offset) : name (name), size (size), offset (offset), subregisters (0) {};
		HRegister (HString name, size_t size, size_t offset, HList<HRegister> subregisters) : name (name), size (size), offset (offset), subregisters (subregisters) {};
		HRegister (const HRegister& reg) : name (reg.name), size (reg.size), offset (reg.offset), subregisters (reg.subregisters) {}
		HRegister (const HRegister&& reg) : name (reg.name), size (reg.size), offset (reg.offset), subregisters (reg.subregisters) {}

		HRegister* addRegister (HRegister* reg) {
			subregisters.push_back (*reg);
			return &subregisters.back();
		};
		HRegister* getRegister (HString string) {
			for (HRegister& reg : subregisters) {
				if (string == reg.name)
					return &reg;
				HRegister* r = reg.getRegister (string);
				if (r) return r;
			}
			return 0;
		}
		void print (int indent = 0) {
			printIndent (indent);
			std::printf ("Register %s s: %d o: %d\n", name.cstr(), size, offset);
			for (HRegister & reg : subregisters) {
				reg.print (indent + 1);
			}
		}
	};
	typedef int64_t HArgIntImmediate;
	typedef double HArgFloatImmediate;
	typedef uint64_t HArgStack;
	struct HArgMem { //segment::[base + index*scale + disp]
		HRegister* segment;
		HRegister* base;
		HRegister* index;
		HArgIntImmediate scale;
		HArgIntImmediate disp;
	};
	struct HInstArgument {
		union { //ordered first because of tighter memory layout
			HArgIntImmediate ival;
			HArgFloatImmediate fval;
			HArgMem mem;
			HRegister* reg;
			HArgStack stackindex;
		};
		HInstArgType type;// size || memoperand || (reg or stack or signed or unsigned)

		void print () {
			switch (type.type) {
			case H_LOCAL_TYPE_REGISTER:
				if (reg)
					printf ("%s", reg->name.cstr());
				else
					printf ("No Reg Def");
				break;
			case H_LOCAL_TYPE_STACK:
				printf ("Stack[%d]", stackindex);
				break;
			case H_LOCAL_TYPE_MEM: {
				bool pre = false;
				if (mem.segment){
					printf ("%s:", mem.segment->name.cstr());
				}
				printf ("[");
				if (mem.base){
					printf ("%s", mem.base->name.cstr());
					pre = true;
				}
				if (mem.index && mem.scale) {
					if(pre)
						printf(" + ");
					printf ("%s*%d", mem.index->name.cstr(), mem.scale);
					pre = true;
				}
				if (mem.disp) {
					if(pre)
						printf(" + ");
					if(mem.disp >= 0)
						printf ("0x%X", mem.disp);
					else
						printf ("%d", mem.disp);
				}
				printf ("]");
			}
			break;
			case H_LOCAL_TYPE_IMM_SIGNED:
				printf ("%d", ival);
				break;
			case H_LOCAL_TYPE_IMM_UNSIGNED:
				printf ("0x%X", ival);
				break;
			case H_LOCAL_TYPE_IMM_FLOAT:
				printf ("%f", fval);
				break;
			}
		}
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
		HInstArgument operands[4];

		void print (int indent = 0) {
			if (instrdef) {
				printIndent (indent);
				printf ("0x%X: %s ", addr, instrdef->mnemonics.cstr());
				for (int i = 0; i < opcount; i++) {
					printf (" Args%d: ", i + 1);
					operands[i].print ();
				}
				if (!instrdef->il_string[opcount])
					printf ("   Has no il_string!");
				printf ("\n");
			} else {
				printIndent (indent);
				printf ("No Def\n");
			}
		}
	};
	struct HBasicBlock {
		HList<HInstruction> instructions;
		HBasicBlock* nextblock;
		HBasicBlock* nextcondblock;
		HInstructionCondition cond;
		size_t addr;
		size_t size;

		void print (int indent = 0) {
			printIndent (indent);
			printf ("BB 0x%x-0x%x t:0x%x f:0x%x\n", addr, addr + size, instructions.back().jumpdest, instructions.back().nojumpdest);
			for (HInstruction& instruction : instructions) {
				instruction.print (indent + 1);
			}
		}
	};
	struct HFunction {
		HId id;
		HId symbolref;
		HList<HBasicBlock> basicblocks;
		HVisibilityType* visibility;
	};

}

#endif // H_FUNCTION_H
