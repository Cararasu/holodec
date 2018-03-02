#ifndef SSAPEEPHOLEOPTIMIZER_H
#define SSAPEEPHOLEOPTIMIZER_H

#include "General.h"
#include "SSA.h"
#include "SSATransformer.h"
#include "PeepholeOptimizer.h"

namespace holodec {

	
	struct SSAPeepholeOptimizer : public SSATransformer {
		
		PeepholeOptimizer* phOpt;

		SSAPeepholeOptimizer();

		virtual bool doTransformation(Binary* binary, Function* function);
	};

}

#endif // SSAPEEPHOLEOPTIMIZER_H
