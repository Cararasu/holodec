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
	
	PeepholeOptimizer* parsePhOptimizer(Architecture* arch, Function* func);
}

#endif // PEEPHOLEOPTIMIZER_H
