#ifndef SSAADDRESSTOBLOCKTRANSFORMER_H
#define SSAADDRESSTOBLOCKTRANSFORMER_H

#include "SSATransformer.h"
namespace holodec {
	struct SSAAddressToBlockTransformer : public SSATransformParser {
		
		virtual void parseExpression (SSABB* basicBlock, SSAExpression* expression);
		
		virtual void parseBlock (SSABB* block);

	};
}

#endif // SSAADDRESSTOBLOCKTRANSFORMER_H
