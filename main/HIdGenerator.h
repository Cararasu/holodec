#ifndef HIDGENEHATOH_H
#define HIDGENEHATOH_H

#include <stdint.h>

namespace holodec {

	typedef uint64_t HId;
	
	class HIdGenerator {
	private:
		HId val = 1;
	public:
		HId next() {
			return val++;
		}
	};
}


#endif // HIDGENEHATOH_H
