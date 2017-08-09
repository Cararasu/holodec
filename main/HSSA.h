
#include "HId.h"
#include "HClass.h"

#define HSSA_LOCAL_USEID_MAX (4)

namespace holodec {

	enum HSSAExprType {
		HSSA_EXPR_INVALID = 0,
		HSSA_EXPR_INPUT,  // Predefined variables, correspond to input arguments
		HSSA_EXPR_UNDEF,  // Predefined variables, correspond to input arguments

		HSSA_EXPR_VALUE,  // Value

		HSSA_EXPR_OP,  // Predefined variables, correspond to input arguments
		// Call - Return
		HSSA_EXPR_BR,  // Branch
		HSSA_EXPR_CALL,  // a call to a function
		HSSA_EXPR_RET,  // a return
		HSSA_EXPR_SYSCALL,  // a syscall
		HSSA_EXPR_TRAP,  // a trap
		// Misc
		// Int,Any... -> Any
		HSSA_EXPR_IF,  // depending on the first value n returns the nth value(for conditional jumps/conditional moves/...)
		// Any... -> Any
		HSSA_EXPR_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		// Any  -> Any
		HSSA_EXPR_EXTEND,  // zero extend a value
		// Any -> Int
		HSSA_EXPR_SPLIT,  // access to part of a variable
		// Any -> Any
		HSSA_EXPR_APPEND,  // combine variables
		HSSA_EXPR_CAST,  // cast to other type

		HSSA_EXPR_MEM,  // addr = base, index, scale, disp
		// Memory
		HSSA_EXPR_STORE, //mem = mem, addr, value
		HSSA_EXPR_LOAD, //value = mem, addr
		
		HSSA_EXPR_FLAG_C,
		HSSA_EXPR_FLAG_A,
		HSSA_EXPR_FLAG_P,
		HSSA_EXPR_FLAG_O,
		HSSA_EXPR_FLAG_Z,
		HSSA_EXPR_FLAG_S,
	};
	enum HSSAOperatorType {
		HSSA_OP_INVALID = 0,
		HSSA_OP_ADD,
		HSSA_OP_SUB,
		HSSA_OP_MUL,
		HSSA_OP_DIV,
		HSSA_OP_MOD,

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
	};
	enum HSSAType {
		HSSA_TYPE_UNKNOWN = 0,
		HSSA_TYPE_INT,
		HSSA_TYPE_UINT,
		HSSA_TYPE_FLOAT,
		HSSA_TYPE_MEM,
	};

	enum HSSAArgType {
		HSSA_ARG_INT = 1,
		HSSA_ARG_UINT,
		HSSA_ARG_FLOAT,
		HSSA_ARG_SSA,
	};
	struct HSSAId{
		HId id;
		HId bbid;
		
		operator bool(){
			return id && bbid;
		}
	};
	
	struct HSSAArg {
		HSSAArgType type;
		union {
			int64_t val;
			uint64_t uval;
			double fval;
			HSSAId ssaId;
		};
		static HSSAArg createArg (int64_t val) {
			HSSAArg arg;
			arg.type = HSSA_ARG_INT;
			arg.val = val;
			return arg;
		}
		static HSSAArg createArg (uint64_t val) {
			HSSAArg arg;
			arg.type = HSSA_ARG_UINT;
			arg.uval = val;
			return arg;
		}
		static HSSAArg createArg (double val) {
			HSSAArg arg;
			arg.type = HSSA_ARG_FLOAT;
			arg.fval = val;
			return arg;
		}
		static HSSAArg createArg (HSSAId val) {
			HSSAArg arg;
			arg.type = HSSA_ARG_SSA;
			arg.ssaId = val;
			return arg;
		}
	};
	inline bool operator != (HSSAArg& lhs, HSSAArg& rhs) {
		return lhs.type != rhs.type || lhs.val != rhs.val;
	}

	struct HSSAExpression {
		HId id;
		HSSAExprType type;
		HSSAOperatorType opType;
		HSSAType rettype;//refers to the return type
		uint64_t retsize;//refers to the return type

		HId instrId;//what instruction this expression refers to

		HLocalBackedLists<HSSAArg, HSSA_LOCAL_USEID_MAX> subExpressions;

		void print (uint64_t indent = 0) {
			printIndent (indent);
			switch (rettype) {
			case HSSA_TYPE_INT:
				printf ("Int%d ", retsize);
				break;
			case HSSA_TYPE_UINT:
				printf ("Uint%d ", retsize);
				break;
			case HSSA_TYPE_FLOAT:
				printf ("Float%d ", retsize);
				break;
			case HSSA_TYPE_MEM:
				printf ("Mem ");
				break;
			}
			printf (" %d = ", id);
			switch (type) {
			case HSSA_EXPR_INVALID:
				printf ("Invalid ");
				break;
			case HSSA_EXPR_INPUT:
				printf ("Input ");
				break;
			case HSSA_EXPR_UNDEF:
				printf ("Undef ");
				break;
			case HSSA_EXPR_VALUE:
				printf ("Value ");
				break;
			case HSSA_EXPR_OP:
				printf ("Op ");
				switch (opType) {
				case HSSA_OP_INVALID:
				default:
					printf ("Inval-Op ");
					break;
				case HSSA_OP_ADD:
					printf ("+ ");
					break;
				case HSSA_OP_SUB:
					printf ("- ");
					break;
				case HSSA_OP_MUL:
					printf ("* ");
					break;
				case HSSA_OP_DIV:
					printf ("/ ");
					break;
				case HSSA_OP_MOD:
					printf ("% ");
					break;
				case HSSA_OP_AND:
					printf ("& ");
					break;
				case HSSA_OP_OR:
					printf ("| ");
					break;
				case HSSA_OP_XOR:
					printf ("^ ");
					break;
				case HSSA_OP_NOT:
					printf ("~ ");
					break;

				case HSSA_OP_E:
					printf ("== ");
					break;
				case HSSA_OP_NE:
					printf ("!= ");
					break;
				case HSSA_OP_L:
					printf ("< ");
					break;
				case HSSA_OP_LE:
					printf ("<= ");
					break;
				case HSSA_OP_G:
					printf ("> ");
					break;
				case HSSA_OP_GE:
					printf (">= ");
					break;
				case HSSA_OP_BAND:
					printf ("& ");
					break;
				case HSSA_OP_BOR:
					printf ("| ");
					break;
				case HSSA_OP_BXOR:
					printf ("^ ");
					break;
				case HSSA_OP_BNOT:
					printf ("~ ");
					break;

				case HSSA_OP_SHR:
					printf (">> ");
					break;
				case HSSA_OP_SHL:
					printf ("<< ");
					break;
				case HSSA_OP_SAR:
					printf ("pow ");
					break;
				case HSSA_OP_SAL:
					printf ("log2 ");
					break;
				case HSSA_OP_ROR:
					printf ("ror ");
					break;
				case HSSA_OP_ROL:
					printf ("rol ");
					break;
				}
				break;
			case HSSA_EXPR_BR:
				printf ("Branch ");
				break;
			case HSSA_EXPR_CALL:
				printf ("Call ");
				break;
			case HSSA_EXPR_RET:
				printf ("Ret ");
				break;
			case HSSA_EXPR_SYSCALL:
				printf ("Syscall ");
				break;
			case HSSA_EXPR_TRAP:
				printf ("Trap ");
				break;
			case HSSA_EXPR_IF:
				printf ("If ");
				break;
			case HSSA_EXPR_BUILTIN:
				printf ("Builtin ");
				break;
			case HSSA_EXPR_EXTEND:
				printf ("Extend ");
				break;
			case HSSA_EXPR_SPLIT:
				printf ("Split ");
				break;
			case HSSA_EXPR_APPEND:
				printf ("Append ");
				break;
			case HSSA_EXPR_CAST:
				printf ("Cast ");
				break;
			case HSSA_EXPR_MEM:
				printf ("Mem ");
				break;
			case HSSA_EXPR_STORE:
				printf ("Store ");
				break;
			case HSSA_EXPR_LOAD:
				printf ("Load ");
				break;
			case HSSA_EXPR_FLAG_C:
				printf ("Flag_C ");
				break;
			case HSSA_EXPR_FLAG_A:
				printf ("Flag_A ");
				break;
			case HSSA_EXPR_FLAG_P:
				printf ("Flag_P ");
				break;
			case HSSA_EXPR_FLAG_O:
				printf ("Flag_O ");
				break;
			case HSSA_EXPR_FLAG_Z:
				printf ("Flag_Z ");
				break;
			case HSSA_EXPR_FLAG_S:
				printf ("Flag_S ");
				break;
			default:
				printf ("Not Defined ");
				break;
			}
			printf ("(");
			for (int i = 0; i < subExpressions.size(); i++) {
				switch (subExpressions[i].type) {
				case HSSA_ARG_INT:
					printf ("%s0x%x,", subExpressions[i].val < 0 ? "-" : "", subExpressions[i].val < 0 ? subExpressions[i].val * -1 : subExpressions[i].val);
					break;
				case HSSA_ARG_UINT:
					printf ("0x%x,", subExpressions[i].uval);
					break;
				case HSSA_ARG_FLOAT:
					printf ("%f,", subExpressions[i].fval);
					break;
				case HSSA_ARG_SSA:
					printf ("%d,", subExpressions[i].ssaId);
					break;
				default:
					printf ("Invalid %d", subExpressions[i].type);
					break;
				}
			}
			printf (")\n");
		}
	};
	struct HSSAPhiNode {
		HId id;
		HSSAExprType type;
		HSSAOperatorType opType;

		HLocalBackedLists<HId, HSSA_LOCAL_USEID_MAX> subExpressions;
	};

	inline bool operator== (HSSAExpression& lhs, HSSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.opType == rhs.opType && lhs.rettype == rhs.rettype && lhs.retsize == rhs.retsize && lhs.subExpressions.size() == rhs.subExpressions.size()) {
			for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
				if (lhs.subExpressions[i] != rhs.subExpressions[i])
					return false;
			}
			return true;
		}
		return false;
	}
	struct HSSABasicBlock {
		HId id;
		//Phi nodes
		HIdList<HSSAExpression> expressions;

		HId bbId;//what basicblock this expression refers to
	};
	struct HSSAFunction {
		HId id;
		HIdList<HSSABasicBlock> basicblocks;

		HId funcId;//what function this expression refers to
	};

}
