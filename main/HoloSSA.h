
#include "HGeneral.h"
#include <stdio.h>
#include "HArchitecture.h"
#include "HFunction.h"

#define HSSA_LOCAL_USEID_MAX (4)

namespace holodec {
	namespace holossa {
		enum HSSAExpressionType {
		    HSSA_TYPE_INPUT,  // Predefined variables, correspond to input arguments

		    // Call - Return
		    HSSA_TYPE_BR,  // Branch
		    HSSA_TYPE_CALL,  // a call to a function
		    HSSA_TYPE_RET,  // a return
		    HSSA_TYPE_SYSCALL,  // a syscall
		    HSSA_TYPE_TRAP,  // a trap
		    // Misc
		    // Int,Any... -> Any
		    HSSA_TYPE_IF,  // depending on the first value n returns the nth value(for conditional jumps/conditional moves/...)
		    // Any... -> Any
		    HSSA_TYPE_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		    // unsigned Any  -> unsigned Any
		    HSSA_TYPE_EXTEND,  // zero extend a value
		    // signed Any  -> signed Any
		    HSSA_TYPE_SEXTEND,  // sign extend a value
		    // Any -> Int
		    HSSA_TYPE_SPLIT,  // access to part of a variable
		    // Any -> Float
		    HSSA_TYPE_FSPLIT,  // access to float part of a variable
		    // Any -> Any
		    HSSA_TYPE_APPEND,  // access to part of a variable
		    // Arithmetic
		    // Unsigned Int... -> Unsigned Int
		    HSSA_TYPE_PLUS,
		    // Signed Int... -> Signed Int
		    HSSA_TYPE_SPLUS,
		    // Float... -> Float
		    HSSA_TYPE_FPLUS,
		    // Unsigned Int... -> Unsigned Int
		    HSSA_TYPE_MINUS,
		    // Signed Int... -> Signed Int
		    HSSA_TYPE_SMINUS,
		    // Float... -> Float
		    HSSA_TYPE_FMINUS,

		    // Unsigned Int... -> Unsigned Int
		    HSSA_TYPE_MUL,
		    // Signed Int... -> Signed Int
		    HSSA_TYPE_SMUL,
		    // Float... -> Float
		    HSSA_TYPE_FMUL,
		    // Unsigned Int... -> Unsigned Int
		    HSSA_TYPE_DIV,
		    // Signed Int... -> Signed Int
		    HSSA_TYPE_SDIV,
		    // Float... -> Float
		    HSSA_TYPE_FDIV,

		    // Unsigned Int, Int -> Unsigned Int
		    HSSA_TYPE_SHR,
		    // Unsigned Int, Int -> Unsigned Int
		    HSSA_TYPE_SHL,
		    // Float, Int -> Float
		    HSSA_TYPE_SAR,
		    // Float, Int -> Float
		    HSSA_TYPE_SAL,
		    // Unsigned Int, Int -> Unsigned Int
		    HSSA_TYPE_ROR,
		    // Unsigned Int, Int -> Unsigned Int
		    HSSA_TYPE_ROL,

		    // Memory
		    // Any, Unsigned Int -> Any
		    HSSA_TYPE_STORE,
		    HSSA_TYPE_LOAD,
		    // Comparison
		    HSSA_TYPE_CMP_E,
		    HSSA_TYPE_CMP_NE,
		    HSSA_TYPE_CMP_L,
		    HSSA_TYPE_CMP_LE,
		    HSSA_TYPE_CMP_G,
		    HSSA_TYPE_CMP_GE,
		    HSSA_TYPE_CMP_NOT,
		    //
		    HSSA_TYPE_AND,
		    HSSA_TYPE_OR,
		    HSSA_TYPE_XOR,
		    // Bit Operators
		    HSSA_TYPE_BINOP_AND,
		    HSSA_TYPE_BINOP_OR,
		    HSSA_TYPE_BINOP_XOR,
		    HSSA_TYPE_BINOP_NOT,
		    // Shifts - Rotates
		    HSSA_TYPE_BINOP_SHR,
		    HSSA_TYPE_BINOP_SHL,
		    HSSA_TYPE_BINOP_SAR,
		    HSSA_TYPE_BINOP_SAL,
		    HSSA_TYPE_BINOP_ROR,
		    HSSA_TYPE_BINOP_ROL,
		    // Casts
		    HSSA_TYPE_CAST_I2F,
		    HSSA_TYPE_CAST_F2I,
		    //...

		};
		struct HSSAExpression {
			HId defId;
			HSSAExpressionType type;
			// MemorySSA additions
			HId useId[HSSA_LOCAL_USEID_MAX];
			HList<HId> moreUseIds;
			HId lastUse;
		};
		struct HSSABasicBlock {
			HId basicblockid;
			HId functionId;

			HMap<HId, HSSAExpression> expressions;
			HIdGenerator gen_expr;

			HId nextBlockTrue;
			HId nextBlockFalse;
		};
		struct HSSAFunction {
			HId functionId;
			HMap<HId, HSSABasicBlock> basicblocks;
			HIdGenerator gen_block;
		};
		
		enum HSSAIRExpressionType{
			HSSAIR_TYPE_INVALID = 0,
			HSSAIR_TYPE_VALUE,
			HSSAIR_TYPE_RESULT,
			HSSAIR_TYPE_REGISTER,
			HSSAIR_TYPE_ARGUMENT,
			HSSAIR_TYPE_STACK,
			HSSAIR_TYPE_TEMP,
			HSSAIR_TYPE_MEM,//mem location in reult
			HSSAIR_TYPE_AGGREGATION
		};
		enum HSSAControlFlowType{
			HSSA_FLOW_INVALID = 0,
			HSSA_FLOW_JUMP,
			HSSA_FLOW_CALL,
			HSSA_FLOW_RET
		};
		struct HSSAParsedExpression {
			HSSAIRExpressionType type;
			HSSAControlFlowType flowtype;
			uint64_t size;
			union {
				HId resultid;
				uint64_t value;
				struct {
					HId index;
					int64_t offset;
					int64_t size;
				} var;
				struct{
					int64_t count;
					HSSAParsedExpression* array;//is allocated by the algorithm and must be freed at somee point
				}aggregation;
			};
		};

		struct HSSAGenerator {
			HArchitecture* arch;
			HIdGenerator gen_expr;

			bool parseFunction ( HFunction* function );
			bool parseInstruction ( HInstruction* instr );
			HSSAParsedExpression parseExpression ( HInstArgument* arguments, holoir::HIRExpression* expression );
		};
	}
}
