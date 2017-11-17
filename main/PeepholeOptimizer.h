#ifndef PEEPHOLEOPTIMIZER_H
#define PEEPHOLEOPTIMIZER_H

#include "HString.h"
#include "Architecture.h"


namespace holodec {

	
	struct PeepholeOptimizer {
		
		//std::vector<>
		
		
		PeepholeOptimizer(HString filename, Architecture* arch){
			
		}
	};
	
	PeepholeOptimizer* parsePhOptimizer(const char* filename, Architecture* arch);
}

#endif // PEEPHOLEOPTIMIZER_H
