#ifndef SSADEADCODEELIMINATIONTRANSFORMER_H
#define SSADEADCODEELIMINATIONTRANSFORMER_H

#include "SSATransformer.h"

namespace holodec {

	class SSADeadCodeEliminationTransformer : public SSATransformer {

		SSARepresentation* ssaRep;
		HList<HId> usecount;
		
		void addNewUse(HId id, std::set<HId>* visited);
		
		virtual void doTransformation (Function* function);
		
	};

}

#endif // SSADEADCODEELIMINATIONTRANSFORMER_H
