#pragma once

#include "String.h"

namespace holodec {

	struct PrimitiveType {
		u64 id;
		String name;

		StringURef type_type;

		Array<u32> possible_sizes;

		bool has_variadic_size() { return possible_size.size() == 0; }
	};

	enum class DataTypeType {
		ePrimitive,
		ePointer,
		eStruct,
	};
	struct DataTypeElement {
		u32 id;
		u64 primitive_handle;
		u32 offset;
		u32 size;
	};
	struct DataType {
		u64 id;
		String name;

		IdArray<DataTypeElement> elements;
	};
}
