#ifndef RINSTRDEFINITION_H
#define RINSTRDEFINITION_H


#include "RString.h"
#include <stdint.h>
#include "RGeneral.h"

namespace holodec {
	
#define R_ARG_IN (0x100)
#define R_ARG_OUT (0x200)

	enum RInstructionCondition {
		R_INSTR_COND_TRUE = 	0x0,//always executed/jumped
		R_INSTR_COND_E,	//equals
		R_INSTR_COND_NE,	//non equals
		R_INSTR_COND_G,	//greater signed
		R_INSTR_COND_GE,	//greater equals signed
		R_INSTR_COND_L,	//lower signed
		R_INSTR_COND_LE,	//lower equals signed
		R_INSTR_COND_A,	//above unsigned
		R_INSTR_COND_AE,	//above equals unsigned
		R_INSTR_COND_B,	//below unsigned
		R_INSTR_COND_BE,	//below equals unsigned
		R_INSTR_COND_C,	//carry
		R_INSTR_COND_NC,	//non carry
		R_INSTR_COND_O,	//overflow
		R_INSTR_COND_NO,	//non overflow
		R_INSTR_COND_NEG,//negative
		R_INSTR_COND_POS,//positive
		R_INSTR_COND_UNK,//unknown
		R_INSTR_COND_FALSE = 0x80000,//not executed/jumped
	};

	enum RInstructionType {
		R_INSTR_TYPE_UNKNOWN = 0,

		R_INSTR_TYPE_NOP,
		R_INSTR_TYPE_JMP,
		R_INSTR_TYPE_RJMP,
		R_INSTR_TYPE_CALL,
		R_INSTR_TYPE_RCALL,
		R_INSTR_TYPE_RET,

		R_INSTR_TYPE_COMP,

		R_INSTR_TYPE_MOV,
		R_INSTR_TYPE_LEA,
		R_INSTR_TYPE_LOAD,
		R_INSTR_TYPE_STORE,
		R_INSTR_TYPE_XCHG,
		R_INSTR_TYPE_EXTEND,
		R_INSTR_TYPE_SEXTEND,

		R_INSTR_TYPE_PUSH,
		R_INSTR_TYPE_POP,
		R_INSTR_TYPE_ENTER,
		R_INSTR_TYPE_LEAVE,

		R_INSTR_TYPE_CMP,

		R_INSTR_TYPE_ADD,
		R_INSTR_TYPE_SUB,
		R_INSTR_TYPE_MUL,
		R_INSTR_TYPE_DIV,
		R_INSTR_TYPE_ABS,
		R_INSTR_TYPE_OR,
		R_INSTR_TYPE_AND,
		R_INSTR_TYPE_XOR,
		R_INSTR_TYPE_NOT,
		R_INSTR_TYPE_NEG,
		R_INSTR_TYPE_CPL,

		R_INSTR_TYPE_SHR,
		R_INSTR_TYPE_SHL,
		R_INSTR_TYPE_ROR,
		R_INSTR_TYPE_ROL,
		R_INSTR_TYPE_SWAP,

		R_INSTR_TYPE_BITTEST,
		R_INSTR_TYPE_BITSET,
		R_INSTR_TYPE_BITRESET,

		R_INSTR_TYPE_NEW,
		R_INSTR_TYPE_IO,
		R_INSTR_TYPE_SWITCH,
		R_INSTR_TYPE_CASE,
		R_INSTR_TYPE_CRYPTO,
		R_INSTR_TYPE_SYNC,

		R_INSTR_TYPE_TRAP,
		R_INSTR_TYPE_SYSCALL,
		R_INSTR_TYPE_HALT,

		R_INSTR_TYPE_UNDEFINED,
		R_INSTR_TYPE_ILLEGAL,
	};
	
	struct RInstrDefinition {//16*8 -> 128 bytes
		RString mnemonics;
		RString formatstring;
		RString il_string;
		size_t type;
		size_t type2;
		uint64_t arg_flags[8];
		RInstructionCondition condition;
		size_t cycles;
		size_t failcycles;
	};

}

#endif // RINSTRDEFINITION_H
