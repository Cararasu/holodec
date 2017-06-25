#ifndef R_FUNCTION_H
#define R_FUNCTION_H

#include "RGeneral.h"
#include "RSection.h"
#include "RInstrDefinition.h"

namespace holodec {



#define R_SET_FLAG(val,flag) val |= flag
#define R_SET_FLAGM(val,flag,mask) val = (val & ~mask) | flag

	enum RLocalType {
		R_LOCAL_TYPE_REGISTER = 1,
		R_LOCAL_TYPE_STACK,
		R_LOCAL_TYPE_MEM,
		R_LOCAL_TYPE_IMM_SIGNED,
		R_LOCAL_TYPE_IMM_UNSIGNED,
		R_LOCAL_TYPE_IMM_FLOAT,
	};
	enum ROpAccess {
		R_OP_ACCESS_READ = 1,
		R_OP_ACCESS_WRITE = 2,
		R_OP_ACCESS_RW = 3,
	};

	struct RInstArgType {
		RLocalType type;//(reg or stack or signed or unsigned)
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
	struct RRegister {
		RString name;
		size_t size;
		size_t offset;
		RList<RRegister> subregisters;

		RRegister() = default;
		RRegister (RString name, size_t size, size_t offset) : name (name), size (size), offset (offset), subregisters (0) {};
		RRegister (RString name, size_t size, size_t offset, RList<RRegister> subregisters) : name (name), size (size), offset (offset), subregisters (subregisters) {};
		RRegister (const RRegister& reg) : name (reg.name), size (reg.size), offset (reg.offset), subregisters (reg.subregisters) {}
		RRegister (const RRegister&& reg) : name (reg.name), size (reg.size), offset (reg.offset), subregisters (reg.subregisters) {}

		RRegister* addRegister (RRegister* reg) {
			subregisters.push_back (*reg);
			return &subregisters.back();
		};
		RRegister* getRegister (RString string) {
			for (RRegister& reg : subregisters) {
				if (string == reg.name)
					return &reg;
				RRegister* r = reg.getRegister (string);
				if (r) return r;
			}
			return 0;
		}
		void print (int indent = 0) {
			printIndent (indent);
			std::printf ("Register %s s: %d o: %d\n", name.cstr(), size, offset);
			for (RRegister & reg : subregisters) {
				reg.print (indent + 1);
			}
		}
	};
	typedef uint64_t RArgIntImmediate;
	typedef double RArgFloatImmediate;
	typedef uint64_t RArgStack;
	struct RArgMem { //[base + index*scale + disp]
		RArgIntImmediate disp;
		RRegister* base;
		RRegister* index;
		RArgIntImmediate scale;
	};
	struct RInstArgument {
		union { //ordered first because of tighter memory layout
			RArgIntImmediate ival;
			RArgFloatImmediate fval;
			RArgMem mem;
			RRegister* reg;
			RArgStack stackindex;
		};
		RInstArgType type;// size || memoperand || (reg or stack or signed or unsigned)

		void print () {
			switch (type.type) {
			case R_LOCAL_TYPE_REGISTER:
				if (reg)
					printf ("%s", reg->name.cstr());
				else
					printf ("No Reg Def");
				break;
			case R_LOCAL_TYPE_STACK:
				printf ("Stack[%d]", stackindex);
				break;
			case R_LOCAL_TYPE_MEM:
				printf ("[%s + %s*%d + %d]", mem.base ? mem.base->name.cstr() : "No Reg Def", mem.index ? mem.index->name.cstr() : "No Reg Def", mem.scale, mem.disp);
				break;
			case R_LOCAL_TYPE_IMM_SIGNED:
				printf ("%d", ival);
				break;
			case R_LOCAL_TYPE_IMM_UNSIGNED:
				printf ("0x%X", ival);
				break;
			case R_LOCAL_TYPE_IMM_FLOAT:
				printf ("%f", fval);
				break;
			}
		}
	};
	struct RInstruction {
		size_t addr;
		size_t size;
		RInstrDefinition* instrdef;

		RInstructionCondition condition;

		size_t nojumpdest;//fall through dst
		size_t jumpdest;//if condition is true
		size_t calldest;//if call succeeds -> creates new function symbol

		size_t opcount;
		RInstArgument operands[6];

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
	struct RBasicBlock {
		RList<RInstruction> instructions;
		RBasicBlock* nextblock;
		RBasicBlock* nextcondblock;
		RInstructionCondition cond;
		size_t addr;
		size_t size;

		void print (int indent = 0) {
			printIndent (indent);
			printf ("BB 0x%x-0x%x t:0x%x f:0x%x\n", addr, addr + size, instructions.back().jumpdest, instructions.back().nojumpdest);
			for (RInstruction& instruction : instructions) {
				instruction.print (indent + 1);
			}
		}
	};
	struct RFunction {
		//RSymbol* symbol;
		RList<RBasicBlock> basicblocks;
		RVisibilityType* visibility;
	};

}

#endif // R_FUNCTION_H
