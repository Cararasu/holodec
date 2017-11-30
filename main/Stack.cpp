#include "Stack.h"

namespace holodec {

	void Stack::relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
		HId newid = gen->next();
		if (replacer)
			replacer (id, newid);
		id = newid;
	}
	Stack invalidStack = {0, "invalid stack", StackType::eRegBacked, StackPolicy::eBottom, 0, 0, nullptr, nullptr};
}
