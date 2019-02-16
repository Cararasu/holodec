#pragma once


namespace holodec {

	struct BitValue;
	struct ConstTypeEval;

	struct VMState {
		bool carry, overflow, underflow;

	};

	typedef bool(*CONST_OP) (BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	typedef bool(*CONST_INT_OP) (BitValue* lhs, u32 rhs, VMState* state, BitValue* result);
	typedef bool(*CONST_BI_OP) (BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	typedef bool(*CONST_BOOLEAN) (BitValue* value, VMState* state, bool* result);


	CONST_INT_OP bitfield_extend;
	CONST_BI_OP bitfield_append;

	CONST_BI_OP bitfield_and;
	CONST_BI_OP bitfield_or;
	CONST_OP bitfield_not;

	CONST_BI_OP bitfield_binary_and;
	CONST_BI_OP bitfield_binary_or;
	CONST_BI_OP bitfield_binary_xor;
	CONST_OP bitfield_binary_not;

	CONST_BI_OP bitfield_shift_right;
	CONST_BI_OP bitfield_shift_left;
	CONST_BI_OP bitfield_rotate_right;
	CONST_BI_OP bitfield_rotate_left;

	struct ConstTypeEval {
		StringRef type;

		CONST_BI_OP addition;
		CONST_BI_OP subtraction;

		CONST_BI_OP multiply;
		CONST_BI_OP division;
		CONST_BI_OP modulo;

		CONST_BI_OP equals;
		CONST_BI_OP less;
		CONST_BI_OP greater;

		CONST_BOOLEAN boolean;
	};

	extern ConstTypeEval bitfield_const_evaluator;

	extern ConstTypeEval twocomplement_const_evaluator;

	extern ConstTypeEval ieee754_const_evaluator;

}