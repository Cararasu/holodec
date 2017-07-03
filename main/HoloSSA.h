
#include "HGeneral.h"
#include <stdio.h>
#include "HArchitecture.h"
#include "HFunction.h"



namespace holodec{
	namespace holossa{
		enum HSSAExpressionType{
			HSSA_TYPE_INPUT,//Predefined variables, correspond to input arguments
			HSSA_TYPE_PLUS,
			HSSA_TYPE_MINUS,
			//...
		};
		struct HSSAExpression{
			HId returnId;
			HSSAExpressionType type;
			HId operands[8];
			HId lastUse;
			
		};
		struct HSSABasicBlock{
			HId basicblockid;
			HId functionId;
			HMap<HId,HSSAExpression> expressions;
			HIdGenerator gen_expr;
			
			HId nextBlockTrue;
			HId nextBlockFalse;
		};
		struct HSSAFunction{
			HId functionId;
			HMap<HId,HSSABasicBlock> basicblocks;
			HIdGenerator gen_block;
			
		};
		
		struct HSSAGenerator{
			
			HArchitecture* arch;
			HList<HRegister*> arguments;
			
			
			bool parseFunction(HFunction* function);
			bool parseInstruction(HInstrDefinition* instrdef);
			
		};
	}
}

