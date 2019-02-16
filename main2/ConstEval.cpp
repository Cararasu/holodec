#include "pch.h"

#include "ConstEval.h"
#include "BitValue.h"

#include <intrin.h>

namespace holodec {

	bool bitfield_boolean(BitValue* value, VMState* state, bool* result) {
		u32 words = value->wordcount();
		u64* ptr = value->word_ptr();
		for (u32 i = words - 1; i >= 0; i--) {
			if (ptr[i]) {
				*result = true;
				return true;
			}
		}
		*result = false;
		return true;
	}

	bool bitfield_and(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		bool lhs_res, rhs_res;
		if (bitfield_boolean(lhs, &lhs_res) && bitfield_boolean(rhs, &rhs_res)) {
			*result = BitValue((lhs_res && rhs_res) ? 1 : 0, 1);
			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_or(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		bool lhs_res, rhs_res;
		if (bitfield_boolean(lhs, &lhs_res) && bitfield_boolean(rhs, &rhs_res)) {
			*result = BitValue((lhs_res || rhs_res) ? 1 : 0, 1);
			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_not(BitValue* val, VMState* state, BitValue* result) {
		bool val_res;
		if (bitfield_boolean(val, &val_res)) {
			*result = BitValue(!val_res ? 1 : 0, 1);
			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}


	bool bitfield_binary_and(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();

			result->reset(bits);

			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();
			u64* res_ptr = result->word_ptr();
			for (u32 i = 0; i < words; i++) {
				res_ptr[i] = lhs_ptr[i] & rhs_ptr[i];
			}
			result->truncate();
			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_binary_or(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();

			result->reset(bits);

			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();
			u64* res_ptr = result->word_ptr();
			for (u32 i = 0; i < words; i++) {
				res_ptr[i] = lhs_ptr[i] | rhs_ptr[i];
			}
			result->truncate();
			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}

	bool bitfield_binary_xor(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();

			result->reset(bits);

			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();
			u64* res_ptr = result->word_ptr();
			for (u32 i = 0; i < words; i++) {
				res_ptr[i] = lhs_ptr[i] ^ rhs_ptr[i];
			}
			result->truncate();
			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_binary_not(BitValue* val, VMState* state, BitValue* result) {
		u32 words = val->wordcount();

		result->reset(val->bitcount);

		u64* val_ptr = val->word_ptr();
		u64* res_ptr = result->word_ptr();
		for (u32 i = 0; i < words; i++) {
			res_ptr[i] = ~val_ptr[i];
		}
		result->truncate();
		state->overflow = false;
		state->carry = false;
		state->underflow = false;
		return true;
	}

	bool bitfield_shift_right(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		
		/*state->overflow = false;
		state->carry = false;
		state->underflow = false;

		result->reset(lhs->bitcount);

		u64* lhs_ptr = lhs->word_ptr();
		u64* rhs_ptr = rhs->word_ptr();
		{//check if definitly an overflow
			if (lhs->bitcount <= result 64 && rhs->bitcount <= 64) {
				result->word_ptr()[0] = lhs_ptr[0] >> rhs_ptr[0];
				result->truncate();
				return true;
			}
			u32 words = rhs->wordcount();
			for (u32 i = 1; i < words; i++) {
				if (rhs_ptr[i]) {
					*result = BitValue(0, lhs->bitcount);
					return true;
				}
			}
			if (rhs_ptr[0] > lhs->bitcount) {
				*result = BitValue(0, lhs->bitcount);
				return true;
			}
		}
		result->truncate();*/
		// WARNING
		return false;
	}
	bool bitfield_shift_left(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {

		}
		// WARNING
		return false;
	}
	bool bitfield_rotate_right(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {

		}
		// WARNING
		return false;
	}
	bool bitfield_rotate_left(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {

		}
		// WARNING
		return false;
	}

	bool bitfield_addition(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits  == rhs->bitcount) {
			u32 words = lhs->wordcount();

			result->reset(bits);
			bool carry = false, overflow = false;

			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();
			u64* res_ptr = result->word_ptr();
			for (u32 i = 0; i < words; i++) {
				res_ptr[i] = lhs_ptr[i] + rhs_ptr[i];
				if (carry) {
					res_ptr[i]++;
					carry = res_ptr[i] <= lhs_ptr[i];
				}
				else {
					carry = res_ptr[i] < lhs_ptr[i];
				}
			}
			result->truncate();

			u32 lastword = words - 1;
			carry = res_ptr[lastword] < lhs_ptr[lastword];

			bool lhs_sign = (lhs_ptr[lastword] & lastbit) != 0;
			bool rhs_sign = (rhs_ptr[lastword] & lastbit) != 0;
			bool res_sign = (res_ptr[lastword] & lastbit) != 0;

			state->overflow = (lhs_sign == rhs_sign) && (lhs_sign != res_sign);
			state->carry = carry;
			state->underflow = false;
			return true;
		}
		else {
			//WARNING
			return false;
		}
	}
	bool bitfield_subtraction(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();

			result->reset(bits);
			bool carry = false, overflow = false;

			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();
			u64* res_ptr = result->word_ptr();
			for (u32 i = 0; i < words; i++) {
				res_ptr[i] = lhs_ptr[i] - rhs_ptr[i];
				if (carry) {
					res_ptr[i]--;
					carry = res_ptr[i] >= lhs_ptr[i];
				}
				else {
					carry = res_ptr[i] > lhs_ptr[i];
				}
			}
			result->truncate();

			u32 lastword = words - 1;

			carry = res_ptr[lastword] < lhs_ptr[lastword];

			bool lhs_sign = (lhs_ptr[lastword] & lastbit) != 0;
			bool rhs_sign = (rhs_ptr[lastword] & lastbit) != 0;
			bool res_sign = (res_ptr[lastword] & lastbit) != 0;

			state->overflow = (lhs_sign != rhs_sign) && (lhs_sign != res_sign);
			state->carry = carry;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}
	
	void extmul(u64 lhs, u64 rhs, u64 *lower, u64 *higher) {
#if defined(__clang__)
#error TODO support clang
#elif defined(__GNUC__) || defined(__GNUG__)
		__int128 result = (__int128)lhs * (__int128)rhs;
		*lower = (u64)result;
		*higher = result >> 64;
#elif defined(_MSC_VER)
		*lower = _umul128(lhs, rhs, higher);
#endif
	}

	bool bitfield_multiply(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();

			result->reset(bits * 2);
			bool carry = false, overflow = false;

			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();
			u64* res_ptr = result->word_ptr();
			for (u32 i = 0; i < words; i++) {
				for (u32 j = 0; j < words; j++) {
					u64 low = 0;
					u64 high = 0;
					extmul(lhs_ptr[i], rhs_ptr[j], &low, &high);
					res_ptr[i + j] += low;
					res_ptr[i + j + 1] += high;
				}
			}
			u32 lastbit = 1 << ((result->bitcount - 1) % 64);

			result->truncate();

			state->overflow = false;
			state->carry = false;
			state->underflow = false;
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_division(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			if (bits <= 64) {
				*result = BitValue(lhs->word_ptr()[0] / rhs->word_ptr()[0], bits);
				state->overflow = false;
				state->carry = false;
				state->underflow = false;
				return true;
			}
			else {
				//TODO implement division for bitcount > 64
			}
		}
		// WARNING
		return false;
	}
	bool bitfield_modulo(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			if (bits <= 64) {
				*result = BitValue(lhs->word_ptr()[0] % rhs->word_ptr()[0], bits);
				state->overflow = false;
				state->carry = false;
				state->underflow = false;
				return true;
			}
			else {
				//TODO implement modulo for bitcount > 64
			}
		}
		// WARNING
		return false;
	}

	bool bitfield_equals(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();
			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();

			state->overflow = false;
			state->carry = false;
			state->underflow = false;

			for (u32 i = 0; i < words; i++) {
				if (lhs_ptr[i] != rhs_ptr[i]) {
					*result = BitValue(0, 1);
					return true;
				}
			}
			*result = BitValue(1, 1);
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_less(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();
			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();

			state->overflow = false;
			state->carry = false;
			state->underflow = false;

			for (u32 i = words - 1; i >= 0; i--) {
				if (!(lhs_ptr[i] < rhs_ptr[i])) {
					*result = BitValue(0, 1);
					return true;
				}
			}
			*result = BitValue(1, 1);
			return true;
		}
		// WARNING
		return false;
	}
	bool bitfield_greater(BitValue* lhs, BitValue* rhs, VMState* state, BitValue* result) {
		u32 bits = lhs->bitcount;
		if (bits == rhs->bitcount) {
			u32 words = lhs->wordcount();
			u64* lhs_ptr = lhs->word_ptr();
			u64* rhs_ptr = rhs->word_ptr();

			state->overflow = false;
			state->carry = false;
			state->underflow = false;

			for (u32 i = words - 1; i >= 0; i--) {
				if (!(lhs_ptr[i] > rhs_ptr[i])) {
					*result = BitValue(0, 1);
					return true;
				}
			}
			*result = BitValue(1, 1);
			return true;
		}
		// WARNING
		return false;
	}

	ConstTypeEval bitfield_const_evaluator = {
		StringRef(),
		bitfield_addition,
		bitfield_subtraction,

		bitfield_multiply,
		bitfield_division,
		bitfield_modulo,

		bitfield_equals,
		bitfield_less,
		bitfield_greater,

		bitfield_boolean
	};
}