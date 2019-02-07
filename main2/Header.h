#pragma once

#include <cassert>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define MAX(lhs, rhs) lhs < rhs ? rhs : lhs
#define MIN(lhs, rhs) lhs > rhs ? rhs : lhs

namespace holodec {

	typedef uint8_t u8;
	typedef uint16_t u16;
	typedef uint32_t u32;
	typedef uint64_t u64;
	typedef int8_t s8;
	typedef int16_t s16;
	typedef int32_t s32;
	typedef int64_t s64;

	typedef float f32;
	typedef double f64;

	enum class Endianess {
		eLittle,
		eBig
	};

}