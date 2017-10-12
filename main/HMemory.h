#ifndef HMEMORY_H
#define HMEMORY_H

#include "HId.h"
#include "HString.h"

namespace holodec {

	struct HMemory {
		HId id;
		HString name;
		uint64_t size;
		
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer = nullptr);
	};

}

#endif // HMEMORY_H
