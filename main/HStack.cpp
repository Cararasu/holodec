#include "HStack.h"

namespace holodec {

	void HStack::relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
		HId newid = gen->next();
		if (replacer)
			replacer (id, newid);
		id = newid;
	}

}
