#ifndef SSATRANSFORMTOC_H
#define SSATRANSFORMTOC_H

#include "SSATransformer.h"
namespace holodec {

	struct SSATransformToC : public SSATransformer {

		virtual void doTransformation (Function* function);
	};

}

#endif // SSATRANSFORMTOC_H
