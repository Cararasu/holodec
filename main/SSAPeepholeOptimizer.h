#ifndef SSAPEEPHOLEOPTIMIZER_H
#define SSAPEEPHOLEOPTIMIZER_H

#include "General.h"
#include "SSA.h"
#include "SSATransformer.h"
namespace holodec {

	
	struct SSAPeepholeOptimizer : public SSATransformer {
		
		
		SSAPeepholeOptimizer();
		
		virtual void doTransformation (Function* function);
	};

}

#endif // SSAPEEPHOLEOPTIMIZER_H
