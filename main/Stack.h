#ifndef HSTACK_H
#define HSTACK_H

#include "HString.h"
#include <stdint.h>
#include "General.h"
#include "Register.h"
namespace holodec {

	enum StackType {
		H_STACK_REGBACKED,
		H_STACK_MEMORY
	};
	enum StackPolicy {
		H_STACKPOLICY_BOTTOM,
		H_STACKPOLICY_TOP
	};
	struct Stack {
		HId id;
		HString name;
		StackType type;
		StackPolicy policy;
		uint64_t count;
		uint64_t wordbitsize;
		StringRef backingMem;
		StringRef trackingReg;
		HList<StringRef> backingRegs;
		
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer = nullptr);
	};

	extern Stack invalidStack;
}

#endif // HSTACK_H
