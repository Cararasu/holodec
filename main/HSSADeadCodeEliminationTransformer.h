#ifndef HSSADEADCODEELIMINATIONTRANSFORMER_H
#define HSSADEADCODEELIMINATIONTRANSFORMER_H

#include "HSSATransformer.h"

namespace holodec {

	class HSSADeadCodeEliminationTransformer : public HSSATransformer {

		HSSARepresentation* ssaRep;
		HList<HId> usecount;
		
		void addNewUse(HId id, std::set<HId>* visited);
		
		virtual void doTransformation (HFunction* function);
		
	};

}

#endif // HSSADEADCODEELIMINATIONTRANSFORMER_H
