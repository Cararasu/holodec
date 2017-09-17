
#ifndef HIR_H
#define HIR_H

#include "HSSA.h"
#include "HId.h"
#include "HStack.h"
#include "HRegister.h"
#include "HArgument.h"

#define HIR_LOCAL_USEID_MAX (4)

namespace holodec {

	class HArchitecture;
	
	enum HIRExprType {
		HIR_EXPR_INVALID = 0,
		HIR_EXPR_UNDEF,
		HIR_EXPR_NOP,

		HIR_EXPR_ASSIGN,//attaches IR val to a reg/arg/tmp/stack

		HIR_EXPR_IF,
		HIR_EXPR_JMP,//jump depending on value
		HIR_EXPR_CJMP,
		HIR_EXPR_OP,
		// Call - Return
		HIR_EXPR_CALL,  // a call to a function
		HIR_EXPR_RETURN,  // a return
		HIR_EXPR_SYSCALL,  // a syscall
		HIR_EXPR_TRAP,  // a trap

		HIR_EXPR_BUILTIN,  // call a builtin(invalidates all previous variables and creates a new def)
		HIR_EXPR_EXTEND,  // zero extend a value
		HIR_EXPR_SPLIT,  // access to part of a variable
		HIR_EXPR_APPEND,  // combine variables
		HIR_EXPR_CAST,  // cast to other type

		HIR_EXPR_MEM,  // addr = base, index, scale, disp, ?segment?
		// Memory
		HIR_EXPR_STORE, //mem = mem, addr, value
		HIR_EXPR_LOAD, //value = mem, addr

		//IR only
		HIR_EXPR_PUSH,
		HIR_EXPR_POP,
		
		HIR_EXPR_VALUE,
		HIR_EXPR_REC,
		HIR_EXPR_REP,
		HIR_EXPR_SIZE,
		HIR_EXPR_BSIZE,
		HIR_EXPR_SEQUENCE,//only for ir gets resolved in ir generation

		HIR_EXPR_FLAG,
	};
	struct HIRExpression {
		HId id;
		HIRExprType type = HIR_EXPR_INVALID;
		uint64_t size = 0;
		HSSAType exprtype = HSSA_TYPE_UNKNOWN;
		struct { //196 bit
			union { //64 bit
				HSSAFlagType flagType;
				HId index;
				HSSAOpType opType;
				HId builtinId;
				HId instrId;
			};
		} mod;
		HLocalBackedList<HArgument, HIR_LOCAL_USEID_MAX> subExpressions;

		bool operator!() {
			return type == HIR_EXPR_INVALID;
		}
		operator bool() {
			return type != HIR_EXPR_INVALID;
		}
		void print(HArchitecture* arch, int indent = 0, bool recursive = true);
	};
	inline bool operator== (HIRExpression& lhs, HIRExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case HIR_EXPR_FLAG:
				return lhs.mod.flagType == rhs.mod.flagType;
			case HIR_EXPR_OP:
				return lhs.mod.opType == rhs.mod.opType;
			case HIR_EXPR_BUILTIN:
				return lhs.mod.index == rhs.mod.index;
			}
		}
		return false;
	}


	struct HIRRepresentation {
		int64_t argcount;
		HString condstring;
		HString irstring;

		HArgument condExpr = HArgument::create();
		HArgument rootExpr = HArgument::create();

		HIRRepresentation() : HIRRepresentation (-1, nullptr, nullptr) {}
		HIRRepresentation (HString irstring) :  HIRRepresentation (-1, nullptr, irstring) {}
		HIRRepresentation (int64_t argcount, HString irstring) : HIRRepresentation (argcount, nullptr, irstring) {}
		HIRRepresentation (HString condstring, HString irstring) : HIRRepresentation (-1, condstring, irstring) {}
		HIRRepresentation (int64_t argcount, HString condstring, HString irstring) : argcount (argcount), condstring (condstring), irstring (irstring) {}

		bool operator!() {
			return !irstring;
		}
		operator bool() {
			return irstring;
		}
		void print (HArchitecture* arch, int indent = 0) {
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

#endif //HIR_H
