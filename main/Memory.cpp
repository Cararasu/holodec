#include "Memory.h"

namespace holodec{
	
	Memory invalidMem = {0, "invalid mem"};
	
	void Memory::relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer) {
		HId newid = gen->next();
		if (replacer)
			replacer (id, newid);
		id = newid;
	}
	
	
}