#ifndef HSTACK_H
#define HSTACK_H

#include "HString.h"
#include <stdint.h>
namespace holodec {

	enum HStackType{
		H_STACK_REGISTER,
		H_STACK_MEMORY
	};
	struct HStack {
		HString name;
		HStackType type;
		uint64_t size;
		uint64_t wordbitsize;
		HString trackingReg;
	};

}

#endif // HSTACK_H
