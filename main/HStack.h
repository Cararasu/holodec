#ifndef HSTACK_H
#define HSTACK_H

#include "HString.h"
#include <stdint.h>
#include "HGeneral.h"
#include "HRegister.h"
namespace holodec {

	enum HStackType {
		H_STACK_REGBACKED,
		H_STACK_MEMORY
	};
	enum HStackPolicy {
		H_STACKPOLICY_BOTTOM,
		H_STACKPOLICY_TOP
	};
	struct HStack {
		HId id;
		HString name;
		HStackType type;
		HStackPolicy policy;
		uint64_t count;
		uint64_t wordbitsize;
		HStringRef backingMem;
		HStringRef trackingReg;
		HList<HStringRef> backingRegs;
		
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer = nullptr);
	};

	extern HStack invalidStack;
}

#endif // HSTACK_H
