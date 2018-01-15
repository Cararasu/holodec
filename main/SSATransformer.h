#ifndef SSATRANSFORMER_H
#define SSATRANSFORMER_H


#include "SSA.h"
namespace holodec {

	class Architecture;
	class Function;
	class SSAExpression;

	struct SSATransformer {
		Architecture* arch;

		virtual void doTransformation (Function* function) = 0;
	};

	struct SSATransformParser : public SSATransformer {
		Function* function;

		virtual void parseBlock (SSABB* block){};
		
		virtual HList<HId>::iterator parseExpression (SSABB* basicBlock, HList<HId>::iterator it) = 0;

		virtual void doTransformation (Function* function);
	};

}

#endif // SSATRANSFORMER_H
