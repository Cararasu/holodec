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


	bool bitfield_extend(BitValue* lhs, u32 rhs, VMState* state, BitValue* result);
	bool bitfield_append(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);

	bool bitfield_and(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_or(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_not(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);

	bool bitfield_binary_and(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_binary_or(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_binary_xor(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_binary_not(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);

	bool bitfield_shift_right(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_shift_left(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_rotate_right(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);
	bool bitfield_rotate_left(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result);

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