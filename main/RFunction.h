#ifndef R_FUNCTION_H
#define R_FUNCTION_H

#include "RGeneral.h"
#include "RSection.h"
#include "RInstrDefinition.h"

namespace radpp {

#define R_LOCAL_TYPE_REGISTER 		(1)
#define R_LOCAL_TYPE_STACK 			(2)
#define R_LOCAL_TYPE_MEM		 	(3)
#define R_LOCAL_TYPE_IMM_SIGNED 	(4)
#define R_LOCAL_TYPE_IMM_UNSIGNED 	(5)
#define R_LOCAL_TYPE_IMM_FLOAT	 	(6)

	
	#define R_SET_FLAG(val,flag) val |= flag
	#define R_SET_FLAGM(val,flag,mask) val = (val & ~mask) | flag
	

	struct RInstArgType { //32 bit
		uint16_t type;//(reg or stack or signed or unsigned)
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
		RRegisterIndex index;
		size_t size;
		size_t offset;
		RList<RRegister> subregisters;

		RRegister* addRegister (RRegister* reg) {
			subregisters.push_back (*reg);
			return &subregisters.back();
		};
		RRegister* getRegister(RRegisterIndex index){
			for(RRegister& reg : subregisters){
				if(reg.index == index)
					return &reg;
				RRegister* r = reg.getRegister(index);
				if(r) return r;
			}
			return 0;
		}
		RRegister* getRegister(RString string){
			for(RRegister& reg : subregisters){
				if(strcmp(string,reg.name) == 0)
					return &reg;
				RRegister* r = reg.getRegister(string);
				if(r) return r;
			}
			return 0;
		}
		void print (int indent = 0) {
			printIndent (indent);
			printf ("Register %s s: %d o: %d\n", name, size, offset);
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
	};
	struct RInstruction {
		size_t addr;
		size_t size;
		RInstrDefinition* instrdef;

		RInstructionCondition condition;
		
		size_t nojumpdest;//fall through dst
		size_t jumpdest;//if condition is true
		size_t calldest;//if call succeeds -> creates new function symbol
		
		RInstArgument operands[8];

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
			printf ("BB 0x%x-0x%x t:0x%x f:0x%x\n", addr, addr + size,instructions.back().jumpdest,instructions.back().nojumpdest);
		}
	};
	struct RFunction {
		//RSymbol* symbol;
		RList<RBasicBlock> basicblocks;
		RVisibilityType* visibility;
	};

}

#endif // R_FUNCTION_H
