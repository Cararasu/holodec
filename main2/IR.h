#pragma once

namespace holodec {
	namespace ir {

		enum class ExprType {
			eInvalid,

			eUndef,
			eValue,

			eOp,
			eFlag,
			eBuiltin,
			eSplit,
			eAppend,
			eCast,

			eInput,
			eOutput,

			eJump,
			eSyscall,
			eTrap,

			ePhi,
			eAssign,

			eStore,
			eLoad,
		};
		enum class OpType {
			eInvalid,

			eAdd,
			eSub,
			eMul,
			eDiv,
			eMod,

			eAnd,
			eOr,
			eNot,

			eEq,
			eNe,
			eLess,
			eLessEq,
			eGreater,
			eGreatEq,

			eBAnd,
			eBOr,
			eBXor,
			eBNot,

			eShr,
			eShl,
			eRor,
			eRol,
		};

		enum class FlagType {
			eInvalid,

			eCarry,
			eOverflow,
			eUnderflow,
		};
		struct Argument {
			
		};
		struct Location {
			u64 address;
			//type
			//regid, memid
		};
		struct Expression {
			//location
		};
	}
}