
#ifndef IR_H
#define IR_H

#include "SSA.h"

#include "Stack.h"
#include "Register.h"
#include "Argument.h"

#define IR_LOCAL_USEID_MAX (4)

namespace holodec {

	struct Architecture;
	
	enum IRExprType {
		IR_EXPR_INVALID = 0,
		IR_EXPR_UNDEF,
		IR_EXPR_NOP,

		IR_EXPR_ASSIGN,//attaches IR val to a reg/arg/tmp/stack

		IR_EXPR_IF,
		IR_EXPR_JMP,//jump depending on value
		IR_EXPR_CJMP,
		IR_EXPR_OP,
		// Call - Return
		IR_EXPR_CALL,  // a call to a function
		IR_EXPR_RETURN,  // a return
		IR_EXPR_SYSCALL,  // a syscall
		IR_EXPR_TRAP,  // a trap

		IR_EXPR_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		IR_EXPR_EXTEND,  // zero extend a value
		IR_EXPR_SPLIT,  // access to part of a variable
		IR_EXPR_APPEND,  // combine variables
		IR_EXPR_CAST,  // cast to other type

		IR_EXPR_MEM,  // addr = base, index, scale, disp, ?segment?
		// Memory
		IR_EXPR_STORE, //mem = mem, addr, value
		IR_EXPR_LOAD, //value = mem, addr

		//IR only
		IR_EXPR_PUSH,
		IR_EXPR_POP,
		
		IR_EXPR_VALUE,
		IR_EXPR_REC,
		IR_EXPR_REP,
		IR_EXPR_SIZE,
		IR_EXPR_BSIZE,
		IR_EXPR_SEQUENCE,//only for ir gets resolved in ir generation

		IR_EXPR_FLAG,
	};
	struct IRExpression {
		HId id;
		IRExprType type = IR_EXPR_INVALID;
		uint32_t size = 0;
		SSAType exprtype = SSAType::eUInt;
		struct { //196 bit
			union { //64 bit
				SSAFlagType flagType;
				HId index;
				SSAOpType opType;
				HId builtinId;
				HId instrId;
			};
		} mod;
		//HLocalBackedList<SSAArgument, IR_LOCAL_USEID_MAX> subExpressions;
		HList<IRArgument> subExpressions;

		bool operator!() {
			return type == IR_EXPR_INVALID;
		}
		operator bool() {
			return type != IR_EXPR_INVALID;
		}
		void print(Architecture* arch, int indent = 0, bool recursive = true);
	};
	inline bool operator== (IRExpression& lhs, IRExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}else{
				return false;
			}
			switch (rhs.type) {
			case IR_EXPR_FLAG:
				return lhs.mod.flagType == rhs.mod.flagType;
			case IR_EXPR_OP:
				return lhs.mod.opType == rhs.mod.opType;
			case IR_EXPR_BUILTIN:
				return lhs.mod.builtinId == rhs.mod.builtinId;
			case IR_EXPR_REC:
				return lhs.mod.instrId == rhs.mod.instrId;
			default:
				return true;
			}
			return true;
		}
		return false;
	}


	struct IRRepresentation {
		uint64_t argcount;
		HString condstring;
		HString irstring;

		IRArgument condExpr = IRArgument::create();
		IRArgument rootExpr = IRArgument::create();

		IRRepresentation() : IRRepresentation (-1, nullptr, "") {}
		IRRepresentation (HString irstring) :  IRRepresentation (-1, nullptr, irstring) {}
		IRRepresentation (uint64_t argcount, HString irstring) : IRRepresentation (argcount, nullptr, irstring) {}
		IRRepresentation (HString condstring, HString irstring) : IRRepresentation (-1, condstring, irstring) {}
		IRRepresentation (uint64_t argcount, HString condstring, HString irstring) : argcount (argcount), condstring (condstring), irstring (irstring) {}

		bool operator!() {
			return !irstring;
		}
		operator bool() {
			return irstring;
		}
		void print (Architecture* arch, int indent = 0) {
			if (condstring) {
				printIndent (indent);
				printf ("Cond-String: %s\n", condstring.cstr());
			}
			if (irstring) {
				printIndent (indent);
				printf ("IL-String: %s\n", irstring.cstr());
			} else {
				printIndent (indent);
				printf ("No IL-String----------------\n");
			}
		}
	};

}

#endif //IR_H
