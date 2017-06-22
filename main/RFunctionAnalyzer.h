#ifndef R_FUNCTIONANALYZER_H
#define R_FUNCTIONANALYZER_H

#include "RSection.h"
#include "RBinary.h"
#include "RFunction.h"
#include "RGeneral.h"

namespace radpp {
	
	class RFunctionAnalyzer {
	protected:
		RBinary* binary;
		
		RList<size_t> addrToAnalyze;
		
		RList<RFunction> functionList;
		RList<RBasicBlock> bbList;
		RList<RInstruction> instructionList;
		
	public:
		RFunctionAnalyzer();
		virtual ~RFunctionAnalyzer();

		virtual bool canAnalyze (RBinary* binary) = 0;

		virtual bool init (RBinary* binary) = 0;
		virtual bool terminate() = 0;
		
		virtual RList<RFunction*> analyzeFunctions (RList<RSymbol*>* functionsymbols);
		

		bool postInstruction(RInstruction* instruction);
		bool postBasicBlock(RBasicBlock* basicblock);
		//can trigger more instruction analyzing, if splitaddr is not on an exact instruction
		bool splitBasicBlock(RBasicBlock* basicblock, size_t splitaddr);
		bool postFunction(RFunction* function);

		virtual void preAnalysis();

		virtual void analyzeFunction (RSymbol* functionsymbol);
		virtual void analyzeInsts (size_t addr,size_t max_inst = 0) = 0;
		
		virtual void postAnalysis();
	};
	

}

#endif // R_FUNCTIONANALYZER_H
