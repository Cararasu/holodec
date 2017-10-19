#ifndef H_CLASS_H
#define H_CLASS_H

#include <vector>
#include "HFunction.h"
#include "HSection.h"


namespace holodec {

	//static, const,
	typedef uint32_t HTypeModifier;

	struct HSection;
	struct HType;
	struct HFunction;

	struct HSubType {
		HString name;
		HId typeId;
		HVisibilityType* visibility;

		size_t offset;
		HList<HTypeModifier> modifiers;
	};
	
	enum HTypeType{
		H_TYPE_AGGREGATION,
		H_TYPE_FUNCTION,
		H_TYPE_POINTER,
		H_TYPE_FLOAT,
		H_TYPE_UINT,
		H_TYPE_INT,
		H_TYPE_UNKNOWN
	};
	struct HType {
		HId id;
		HString name;
		HTypeType type;
		
		HVisibilityType* visibility;

		size_t size;
		HList<HSubType> fields;//for aggregates
	};

	struct HClass {
		HId id;
		HString name;
		HId superClassId;

		HId typeId;
		HList<HFunction*> functions;
	};

}

#endif // H_CLASS_H
