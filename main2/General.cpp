#include "pch.h"

#include "Array.h"

namespace holodec {

	void* allocate(size_t size, size_t alignment) {
		return malloc(size);
	}
	void* reallocate(void* data, size_t size, size_t alignment) {
		return realloc(data, size);
	}

	Allocator nop_allocator = {
		allocate,
		reallocate,
		free,
	};
}