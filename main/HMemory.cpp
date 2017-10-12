#include "HMemory.h"

namespace holodec{
	
	
	void HMemory::relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
		HId newid = gen->next();
		if (replacer)
			replacer (id, newid);
		id = newid;
	}
}