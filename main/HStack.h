#ifndef HSTACK_H
#define HSTACK_H

#include "HString.h"
#include <stdint.h>
#include "HGeneral.h"
#include "HRegister.h"
namespace holodec {

	enum HStackType {
		H_STACK_REGISTER,//register backed
		H_STACK_BUILTIN,
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
		HList<HRegister> regs;
		uint64_t wordbitsize;
		HString trackingReg;

		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer = nullptr) {
			HId newid = gen->next();
			if(replacer)
				replacer(id,newid);
			id = newid;
		}
	};

}

#endif // HSTACK_H
