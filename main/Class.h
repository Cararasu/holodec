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
		HString name;
		HId typeId;
		VisibilityType* visibility;

		size_t offset;
		HList<TypeModifier> modifiers;
	};
	
	enum TypeType{
		H_TYPE_AGGREGATION,
		H_TYPE_FUNCTION,
		H_TYPE_POINTER,
		H_TYPE_FLOAT,
		H_TYPE_UINT,
		H_TYPE_INT,
		H_TYPE_UNKNOWN
	};
	struct Type {
		HId id;
		HString name;
		TypeType type;
		
		VisibilityType* visibility;

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
