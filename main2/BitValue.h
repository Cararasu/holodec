#pragma once

namespace holodec {

	struct BitValue {
		union {
			u64 value[2];
			struct {
				u64* bit_ptr;
				Allocator* allocator;
			};
		};
		u32 bitcount;

		constexpr u32 wordcount() const {
			return (bitcount + 63) / 64;
		}
		u64* word_ptr() {
			if (bitcount <= 128)	return value;
			else					return bit_ptr;
		}
		void truncate() {
			if(bitcount) word_ptr()[wordcount() - 1] &= (1 << (bitcount % 64)) - 1;
		}
		// only for values where bitcount <= 64
		void free() {
			if (bitcount > 128) {
				t_free<u64>(allocator, bit_ptr);
				bit_ptr = nullptr;
				bitcount = 0;
			}
		}
		// only for values where bitcount <= 64
		void set_value(u64 value, u32 bitcount) {
			this->value[0] = value;
			this->value[1] = 0;
			this->bitcount = bitcount;
			truncate();
		}
		// only for values where 64 < bitcount <= 128
		void set_value(u64 value1, u64 value2, u32 bitcount) {
			this->value[0] = value1;
			this->value[1] = value2;
			this->bitcount = bitcount;
			truncate();
		}
		// only for values where bitcount > 128
		void set_value_ptr(u64* bit_ptr, u32 bitcount) {
			this->bitcount = bitcount;
			u32 words = wordcount();
			this->bit_ptr = t_allocate<u64>(allocator, words);
			memcpy(this->bit_ptr, bit_ptr, words * 8);
			truncate();
		}
		void reset(u32 bitcount, Allocator* allocator = nullptr) {
			free();
			this->allocator = allocator;
			this->bitcount = bitcount;

			if (bitcount > 128) {
				u32 words = wordcount();
				this->bit_ptr = t_allocate<u64>(allocator, words);
			}
			memset(word_ptr(), 0, wordcount() * 8);
		}

		BitValue() {
			set_value(0, 0);
		}
		BitValue(u64 value, u32 bitcount) {
			set_value(value, bitcount);
		}
		BitValue(u64* values, u32 bitcount, Allocator* allocator = nullptr) {
			if (bitcount <= 128) {
				set_value(values[0], values[1], bitcount);
			}
			else {
				this->allocator = allocator;
				set_value_ptr(values, bitcount);
			}
		}
		BitValue(const BitValue& bitvalue) {
			if (bitvalue.bitcount <= 128) {
				set_value(bitvalue.value[0], bitvalue.value[1], bitvalue.bitcount);
			}
			else {
				this->allocator = bitvalue.allocator;
				set_value_ptr(bitvalue.bit_ptr, bitvalue.bitcount);
			}
		}
		BitValue(BitValue&& bitvalue) {
			if (bitvalue.bitcount <= 128) {
				set_value(bitvalue.value[0], bitvalue.value[1], bitvalue.bitcount);
			}
			else {
				this->bit_ptr = bitvalue.bit_ptr;
				this->allocator = bitvalue.allocator;
				this->bitcount = bitvalue.bitcount;

				bitvalue.bit_ptr = nullptr;
				bitvalue.allocator = nullptr;
				bitvalue.bitcount = 0;
			}
		}
		BitValue& operator=(const BitValue& bitvalue) {
			if (bitvalue.bitcount <= 128) {
				set_value(bitvalue.value[0], bitvalue.value[1], bitvalue.bitcount);
			}
			else {
				this->allocator = bitvalue.allocator;
				set_value_ptr(bitvalue.bit_ptr, bitvalue.bitcount);
			}
			return *this;
		}
		~BitValue() {
			free();
		}

		void print(FILE* file) {
			fprintf(file, "0x");
			u64* ptr = word_ptr();
			for (u32 i = 0; i < wordcount(); i++) {
				fprintf(file, "%" PRIx64, ptr[i]);
			}
		}
	};

	inline bool operator==(BitValue& lhs, BitValue& rhs) {
		if (lhs.bitcount == rhs.bitcount) {
			return memcmp(lhs.word_ptr(), rhs.word_ptr(), lhs.wordcount() * 8) == 0;
		}
		return false;
	}

}