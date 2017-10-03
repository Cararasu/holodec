#ifndef HSSAPHINODEGENERATOR_H
#define HSSAPHINODEGENERATOR_H

#include "HSSATransformer.h"

namespace holodec {

	
	struct HSSARegDef{
		HId ssaId;
		HId regId, parentId;
		uint64_t offset, size;
	};
	
	struct HSSAPhiNodeGenerator : public HSSATransformer {
		
		
		
		virtual void doTransformation (HFunction* function);
	};

}

#endif // HSSAPHINODEGENERATOR_H
