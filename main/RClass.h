#ifndef R_CLASS_H
#define R_CLASS_H

#include <vector>
#include "RFunction.h"
#include "RSection.h"

namespace radpp {

	//static, const,
	typedef uint32_t RTypeModifier;

	struct RSection;
	struct RType;
	struct RFunction;

	struct RSubType {
		const char* name;
		RType* type;
		RVisibilityType* visibility;

		size_t offset;
		size_t size;

		RList<RTypeModifier> modifiers;
		RList<RSection*> subsections;
	};

	struct RType {
		const char* name;
		//Aggregate
		//Function
		//Pointer
		//Base
		RVisibilityType* visibility;

		size_t size;//maybe not?

		RList<RSubType> fields;//for aggregates
	};

	struct RClass {
		char* name;
		RClass* super;

		RType* type;
		RList<RFunction*> functions;
	};

}

#endif // R_CLASS_H
