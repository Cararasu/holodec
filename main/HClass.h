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
		const char* name;
		HType* type;
		HVisibilityType* visibility;

		size_t offset;
		size_t size;

		HList<HTypeModifier> modifiers;
		HList<HSection*> subsections;
	};

	struct HType {
		const char* name;
		//Aggregate
		//Function
		//Pointer
		//Base
		HVisibilityType* visibility;

		size_t size;//maybe not?

		HList<HSubType> fields;//for aggregates
	};

	struct HClass {
		char* name;
		HClass* super;

		HType* type;
		HList<HFunction*> functions;
	};

}

#endif // H_CLASS_H
