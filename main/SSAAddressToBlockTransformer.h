#ifndef SSAADDRESSTOBLOCKTRANSFORMER_H
#define SSAADDRESSTOBLOCKTRANSFORMER_H

#include "SSATransformer.h"
namespace holodec {
	struct SSAAddressToBlockTransformer : public SSATransformer {

		virtual bool doTransformation(Binary* binary, Function* function);

	};
}

#endif // SSAADDRESSTOBLOCKTRANSFORMER_H
