#ifndef HSSAPHINODEGENERATOR_H
#define HSSAPHINODEGENERATOR_H

#include "HSSATransformer.h"

namespace holodec {

	struct HSSAPhiNodeGenerator : public HSSATransformer {

		virtual void doTransformation (HFunction* function);
	};

}

#endif // HSSAPHINODEGENERATOR_H
