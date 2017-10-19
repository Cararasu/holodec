#include "HStack.h"

namespace holodec {

	void HStack::relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
		HId newid = gen->next();
		if (replacer)
			replacer (id, newid);
		id = newid;
	}
	HStack invalidStack = {0, "invalid stack", H_STACK_BUILTIN, H_STACKPOLICY_BOTTOM, 0, 0, nullptr, nullptr};
}
