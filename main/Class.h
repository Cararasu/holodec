#ifndef H_CLASS_H
#define H_CLASS_H

#include <vector>
#include "Function.h"
#include "Section.h"


namespace holodec {

	//static, const,
	typedef uint32_t TypeModifier;

	struct Section;
	struct Type;
	struct Function;

	struct SubType {
		HId typeId;
		HString name;

		size_t offset;
		HList<TypeModifier> modifiers;
	};
	
	enum TypeType{
		TYPE_AGGREGATION,
		TYPE_FUNCTION,
		TYPE_POINTER,
		TYPE_FLOAT,
		TYPE_UINT,
		TYPE_INT,
		TYPE_UNKNOWN
	};
	struct Type {
		HId id;
		HString name;
		TypeType type;

		size_t size;
		HList<SubType> fields;//for aggregates
	};

	struct HClass {
		HId id;
		HString name;
		HId superClassId;

		HId typeId;
		HList<Function*> functions;
	};

}

#endif // H_CLASS_H
