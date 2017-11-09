#ifndef HMEMORY_H
#define HMEMORY_H


#include "HString.h"
#include "HIdList.h"

namespace holodec {

	struct Memory {
		HId id;
		HString name;
		uint64_t size;
		
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer = nullptr);
	};

	extern Memory invalidMem;
}

#endif // HMEMORY_H
