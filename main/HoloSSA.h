
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

		};

		enum HSSAIRExpressionType {
			HSSAIR_TYPE_INVALID = 0,
			HSSAIR_TYPE_RESULT,
			HSSAIR_TYPE_REGISTER,
			HSSAIR_TYPE_ARGUMENT,
			HSSAIR_TYPE_STACK,
			HSSAIR_TYPE_TEMP,
			HSSAIR_TYPE_MEM,//mem location in reult
			HSSAIR_TYPE_AGGREGATION
		};
		enum HSSAControlFlowType {
			HSSA_FLOW_INVALID = 0,
			HSSA_FLOW_JUMP,
			HSSA_FLOW_CALL,
			HSSA_FLOW_RET
		};
		enum HSSANodeType {
			HSSA_NODE_VAL,
			HSSA_NODE_MEM,
			HSSA_NODE_OP,
		};
		enum HSSAOperatorType {
			HSSA_OP_ADD,
			HSSA_OP_SUB,
			HSSA_OP_MUL,
			HSSA_OP_DIV,

			HSSA_OP_AND,
			HSSA_OP_OR,
			HSSA_OP_XOR,
			HSSA_OP_NOT,

			HSSA_OP_E,
			HSSA_OP_NE,
			HSSA_OP_L,
			HSSA_OP_LE,
			HSSA_OP_G,
			HSSA_OP_GE,

			HSSA_OP_BAND,
			HSSA_OP_BOR,
			HSSA_OP_BXOR,
			HSSA_OP_BNOT,

			HSSA_OP_SHR,
			HSSA_OP_SHL,
			HSSA_OP_SAR,
			HSSA_OP_SAL,
			HSSA_OP_ROR,
			HSSA_OP_ROL,
			// Memory
			HSSA_OP_STORE,
			HSSA_OP_LOAD,
			// Casts
			HSSA_OP_CAST_I2F,
			HSSA_OP_CAST_F2I,
		};
		struct HSSANode {
			HSSANodeType type;
			HId defId;
			HId useId[HSSA_LOCAL_USEID_MAX];
			HList<HId> moreUseIds;
			HId lastUse;
		};
		struct HSSABasicBlock {
			HId basicblockid;
			HId functionId;

			HMap<HId, HSSANode> expressions;
			HIdGenerator gen_expr;

			HId nextBlockTrue;
			HId nextBlockFalse;
		};
		struct HSSAFunction {
			HId functionId;
			HMap<HId, HSSABasicBlock> basicblocks;
			HIdGenerator gen_block;
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
				struct {
					int64_t count;
					HSSAParsedExpression* array;//is allocated by the algorithm and must be freed at somee point
				} aggregation;
			};
		};

		struct HSSAExpression {
			HInstruction* instr;
			//HSSANode
		};

		struct HSSAGenerator {
			HArchitecture* arch;
			HIdGenerator gen_expr;

			bool parseFunction (HFunction* function);
			bool parseInstruction (HInstruction* instr);
			HSSAParsedExpression parseExpression (HInstArgument* arguments, HIRExpression* expression);
		};
	}
}
