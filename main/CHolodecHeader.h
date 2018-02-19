
#ifndef CHOLODECHEADER_H
#define CHOLODECHEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#define SSA_EXPR_CONTROL_FLOW		(0x1000)
#define SSA_EXPR_TRANSPARENT_NODE		(0x2000)//TODO rename as this is a bad name
#define SSA_EXPR_MEMWRITE			(0x4000)

#define EXPR_IS_CONTROLFLOW(type) ((uint64_t)(type) & SSA_EXPR_CONTROL_FLOW)
#define EXPR_IS_TRANSPARENT(type) ((uint64_t)(type) & SSA_EXPR_TRANSPARENT_NODE)

#define EXPR_HAS_SIDEEFFECT(type) ((uint64_t)(type) & (SSA_EXPR_CONTROL_FLOW | SSA_EXPR_MEMWRITE))

typedef uint32_t HId;

enum HRegTrackType {
	REG_TRACK_TRACKED = 0,
	REG_TRACK_VOLATILE
};
enum HRegType {
	REG_OTHER = 0,
	REG_GPR,
	REG_ADDRESS,
	REG_FLOAT,
	REG_VEC,
	REG_STACKPTR,
	REG_INSTRPTR,
	REG_FLAG,
	REG_CONTROL,
	REG_DEBUG,
	REG_SEGMENT
};
enum HInstructionType {
	INSTR_TYPE_UNKNOWN = 0,

	INSTR_TYPE_NOP,
	INSTR_TYPE_JMP,
	INSTR_TYPE_CJMP,
	INSTR_TYPE_CALL,
	INSTR_TYPE_RCALL,
	INSTR_TYPE_RET,

	INSTR_TYPE_COMP,

	INSTR_TYPE_MOV,
	INSTR_TYPE_LEA,
	INSTR_TYPE_LOAD,
	INSTR_TYPE_STORE,
	INSTR_TYPE_XCHG,
	INSTR_TYPE_EXTEND,

	INSTR_TYPE_PUSH,
	INSTR_TYPE_POP,
	INSTR_TYPE_ENTER,
	INSTR_TYPE_LEAVE,

	INSTR_TYPE_CMP,

	INSTR_TYPE_ADD,
	INSTR_TYPE_SUB,
	INSTR_TYPE_MUL,
	INSTR_TYPE_DIV,
	INSTR_TYPE_ABS,
	INSTR_TYPE_OR,
	INSTR_TYPE_AND,
	INSTR_TYPE_XOR,
	INSTR_TYPE_NOT,
	INSTR_TYPE_NEG,
	INSTR_TYPE_CPL,

	INSTR_TYPE_SHR,
	INSTR_TYPE_SHL,
	INSTR_TYPE_ROR,
	INSTR_TYPE_ROL,
	INSTR_TYPE_SWAP,

	INSTR_TYPE_BITTEST,
	INSTR_TYPE_BITSET,
	INSTR_TYPE_BITRESET,

	INSTR_TYPE_NEW,
	INSTR_TYPE_IO,
	INSTR_TYPE_SWITCH,
	INSTR_TYPE_CASE,
	INSTR_TYPE_CRYPTO,
	INSTR_TYPE_SYNC,

	INSTR_TYPE_TRAP,
	INSTR_TYPE_SYSCALL,
	INSTR_TYPE_HALT,

	INSTR_TYPE_UNDEFINED,
	INSTR_TYPE_ILLEGAL,
};

enum HStackType {
	STACK_REGBACKED,
	STACK_MEMORY
};
enum HStackPolicy {
	STACKPOLICY_BOTTOM,
	STACKPOLICY_TOP
};

enum HSSAExprType {
	SSA_EXPR_INVALID	= 0x0,

	SSA_EXPR_LABEL		= 0x10,
	SSA_EXPR_UNDEF		= 0x11,
	SSA_EXPR_NOP		= 0x12,

	SSA_EXPR_OP			= 0x13,
	SSA_EXPR_LOADADDR	= 0x14,
	SSA_EXPR_FLAG		= 0x15,
	SSA_EXPR_BUILTIN	= 0x16,
	SSA_EXPR_EXTEND		= 0x17,
	SSA_EXPR_UPDATEPART	= SSA_EXPR_TRANSPARENT_NODE | 0x19,
	SSA_EXPR_APPEND		= 0x1A,
	SSA_EXPR_CAST		= 0x1B,

	SSA_EXPR_INPUT		= 0x21,
	SSA_EXPR_OUTPUT		= 0x22,

	SSA_EXPR_CALL		= SSA_EXPR_CONTROL_FLOW | 0x23,
	SSA_EXPR_RETURN		= SSA_EXPR_CONTROL_FLOW | 0x24,
	SSA_EXPR_SYSCALL	= SSA_EXPR_CONTROL_FLOW | 0x25,
	SSA_EXPR_TRAP		= SSA_EXPR_CONTROL_FLOW | 0x26,

	SSA_EXPR_PHI		= SSA_EXPR_TRANSPARENT_NODE | 0x31,
	SSA_EXPR_ASSIGN		= 0x32,

	SSA_EXPR_JMP		= SSA_EXPR_CONTROL_FLOW | 0x41,
	SSA_EXPR_CJMP		= SSA_EXPR_CONTROL_FLOW | 0x42,
	SSA_EXPR_MULTIBR	= SSA_EXPR_CONTROL_FLOW | 0x43,

	SSA_EXPR_MEMACCESS	= 0x50,
	SSA_EXPR_PUSH		= SSA_EXPR_MEMWRITE | 0x54,
	SSA_EXPR_POP		= 0x55,
	SSA_EXPR_STORE		= SSA_EXPR_MEMWRITE | 0x58,
	SSA_EXPR_LOAD		= 0x59,

};
enum HSSAExprLocation {
	SSA_LOCATION_NONE = 0,
	SSA_LOCATION_REG,
	SSA_LOCATION_STACK,
	SSA_LOCATION_MEM,
	SSA_LOCATION_BLOCK,
};
enum HSSAFlagType {
	SSA_FLAG_UNKNOWN = 0,
	SSA_FLAG_C,
	SSA_FLAG_O,
	SSA_FLAG_U,
};
enum HSSAOpType {
	SSA_OP_INVALID = 0,
	SSA_OP_ADD,
	SSA_OP_SUB,
	SSA_OP_MUL,
	SSA_OP_DIV,
	SSA_OP_MOD,

	SSA_OP_AND,
	SSA_OP_OR,
	SSA_OP_XOR,
	SSA_OP_NOT,

	SSA_OP_EQ,
	SSA_OP_NE,
	SSA_OP_LOWER,
	SSA_OP_LE,
	SSA_OP_GREATER,
	SSA_OP_GE,

	SSA_OP_BAND,
	SSA_OP_BOR,
	SSA_OP_BXOR,
	SSA_OP_BNOT,

	SSA_OP_SHR,
	SSA_OP_SHL,
	SSA_OP_SAR,
	SSA_OP_SAL,
	SSA_OP_ROR,
	SSA_OP_ROL,
};
enum HSSAArgType {
	SSA_ARGTYPE_UNDEF = 0x0,
	SSA_ARGTYPE_SINT,
	SSA_ARGTYPE_UINT,
	SSA_ARGTYPE_FLOAT,
	SSA_ARGTYPE_ID,
	SSA_ARGTYPE_OTHER
};
enum HSSAType {
	SSA_TYPE_UNKNOWN = 0,
	SSA_TYPE_INT,
	SSA_TYPE_UINT,
	SSA_TYPE_FLOAT,
	SSA_TYPE_PC,
	SSA_TYPE_MEMACCESS,
};

typedef struct {
	HId refId;
	HId index;
} HReference;




#ifdef __cplusplus
}
#endif

#endif //CHOLODECHEADER_H
