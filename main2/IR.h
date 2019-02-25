#pragma once

namespace holodec {
	namespace ir {

		enum class LocationType {
			eInvalid,

			eRegister,
			eMemory
		};

		struct Location {
			LocationType type;

			u64 address;
			u32 ref_id;
		};

		enum class ArgType {
			eInvalid,
			eExpression,
			ePhi
		};

		struct Argument {
			ArgType type;

			u32 block_id;
			u32 expr_id;

			Location location;
		};

		struct BlockArgument {
			u32 block_id;
			Argument arg;
		};

		enum class ExprType {
			eInvalid,

			eUndef,
			eValue,

			eOp,
			eFlag,
			eBuiltin,
			eCast,

			eInput,
			eOutput,

			eAssign,

			eStore,
			eLoad,
		};

		enum class OpType {
			eInvalid,

			eSplit,
			eAppend,

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
			eGreater,

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

		struct PhiExpression {
			u32 id;

			// block_id is the incoming block
			// the argument refers to the actual expression
			StaticDynArray<BlockArgument, 4> block_args;
			StaticDynArray<Location, 2> locations;
		};

		struct Expression {
			u32 id;

			ExprType type;
			OpType op_type;

			BitValue value;

			Argument arg[3];

			StaticDynArray<Location, 2> locations;
		};

		struct BasicBlock {
			u32 id;

			DynArray<u32> phi_expressions;
			DynArray<u32> expressions;

			IdArray<Expression> expressions;

			// if block_id of jump_dest is set then the target is block with the id of block_id
			// if the block_id is 0 then the argument refers to the target
			BlockArgument jump_dest;

			// the condition makes the jump conditional if set
			Argument jump_cond;
		};
	}
}