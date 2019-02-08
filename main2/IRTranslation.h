#pragma once

namespace holodec{

struct FileData;
struct DecompContext;
namespace translation {

	const u32 MAX_SUBEXPRESSIONS = 4;

	bool parse_all_ir_strings(DecompContext* context);
	bool parse_ir_string(DecompContext* context, FileData* fdata);

	struct BitValue {
		union {
			u64 bits;
			u64* data;
		};
		u32 bitcount;
	};

	inline bool operator==(BitValue& lhs, BitValue& rhs) {
		if (lhs.bitcount == rhs.bitcount) {
			if (lhs.bitcount <= 64) {
				return lhs.bits == rhs.bits;
			}
			else {
				return memcmp(lhs.data, rhs.data, 8*(lhs.bitcount / 64)) == 0;
			}
		}
		return false;
	}

	struct VMState {
		bool carry, overflow, underflow;
	};

	struct ConstExprEval {
		StringRef type;

		BitValue(*addition) (BitValue& lhs, BitValue& rhs, VMState* state, u32 result_bitcount);
		BitValue(*subtraction) (BitValue& lhs, BitValue& rhs, VMState* state, u32 result_bitcount);

		BitValue(*multiply) (BitValue& lhs, BitValue& rhs, VMState* state, u32 result_bitcount);
		BitValue(*division) (BitValue& lhs, BitValue& rhs, VMState* state, u32 result_bitcount);
		BitValue(*modulo) (BitValue& lhs, BitValue& rhs, VMState* state, u32 result_bitcount);
	};

	enum class ExpressionType {
		eInvalid,
		eValue,
		eArgument,
		eTemporary,
		eRegister,
		eMemory,
		eStack,
		eBuiltin,
		eRecursive,
		eOp,
		eExtract,
		eCast,
		eInstructionSize,
		eWordSize,
		eBitSize,
	};
	enum class OpType {
		eInvalid,

		eExtend,
		eAppend,

		eCarryFlag,
		eOverflowFlag,
		eUnderflowFlag,

		eAdd,
		eSub,
		eMul,
		eDiv,
		eMod,

		eAnd,
		eOr,
		eNot,

		eEq,
		eNeq,
		eLess,
		eLessEq,
		eGreater,
		eGreaterEq,

		eBAnd,
		eBOr,
		eBXor,
		eBNot,

		eShr,
		eShl,
		eRor,
		eRol
	};

	struct Expression {
		u32 id = 0;
		ExpressionType type = ExpressionType::eInvalid;
		OpType op_type = OpType::eInvalid;

		u32 index = 0;
		StringRef ref;
		BitValue value;

		StringRef typeref;
		u32 size_id = 0;

		u32 offset_id = 0;

		StringRef cast_typeref;
		u32 cast_size_id = 0;

		u32 sub_expressions[MAX_SUBEXPRESSIONS] = {0, 0, 0, 0};
	};

	inline bool operator==(Expression& lhs, Expression& rhs) {
		return lhs.type == rhs.type &&
			lhs.index == rhs.index &&
			lhs.ref == rhs.ref &&
			lhs.value == rhs.value &&
			lhs.size_id == rhs.size_id &&
			lhs.offset_id == rhs.offset_id &&
			lhs.sub_expressions[0] == rhs.sub_expressions[0] &&
			lhs.sub_expressions[1] == rhs.sub_expressions[1] &&
			lhs.sub_expressions[2] == rhs.sub_expressions[2] &&
			lhs.sub_expressions[3] == rhs.sub_expressions[3];
	}

	struct IRLine {
		String str;

		u32 label_id = 0;
		u32 write_id = 0;
		u32 expr_id = 0;
		u32 cond_id = 0;

		IRLine(String&& line) : str(line), label_id(0), write_id(0), expr_id(0), cond_id(0) {}

		void print(DecompContext* context, u32 indent = 0, FILE * file = stdout);
	};

	struct IRTranslation {
		u32 argcount;
		DynArray<IRLine> condition;
		DynArray<IRLine> code;

		void print(u32 indent = 0, FILE * file = stdout);
	};

	struct IRExprStore {
		IdArray<Expression> exprs;

		Expression* get(u32 id) {
			return exprs.get(id);
		}
		u32 insert(Expression& new_expr) {
			for (Expression& expr : exprs) {
				if (expr == new_expr) return expr.id;
			}
			return exprs.insert(new_expr);
		}
	};
}
}
