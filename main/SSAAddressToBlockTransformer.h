#ifndef SSAADDRESSTOBLOCKTRANSFORMER_H
#define SSAADDRESSTOBLOCKTRANSFORMER_H

#include "SSATransformer.h"
namespace holodec {
	struct SSAAddressToBlockTransformer : public SSATransformParser {
		
		virtual HList<HId>::iterator parseExpression (SSABB* basicBlock, HList<HId>::iterator it);
		
		virtual void parseBlock (SSABB* block);

	};
}

#endif // SSAADDRESSTOBLOCKTRANSFORMER_H
