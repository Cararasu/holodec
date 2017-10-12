#ifndef HSSADEADCODEELIMINATIONTRANSFORMER_H
#define HSSADEADCODEELIMINATIONTRANSFORMER_H

#include "HSSATransformer.h"

namespace holodec {

	class HSSADeadCodeEliminationTransformer : public HSSATransformer {

		virtual void doTransformation (HFunction* function);
		
	};

}

#endif // HSSADEADCODEELIMINATIONTRANSFORMER_H
