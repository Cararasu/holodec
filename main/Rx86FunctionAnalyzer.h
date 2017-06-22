#ifndef R_X86FUNCTIONANALYZER_H
#define R_X86FUNCTIONANALYZER_H

#include "RFunctionAnalyzer.h"
#include "RGeneral.h"

#include <capstone.h>

namespace holox86 {
	
	using namespace holodec;
	
	class Rx86FunctionAnalyzer : public RFunctionAnalyzer {
	private:
		csh handle;
	public:
		Rx86FunctionAnalyzer();
		~Rx86FunctionAnalyzer();

		virtual bool canAnalyze (RBinary* binary);
		
		virtual bool init (RBinary* binary);
		virtual bool terminate();
		
		virtual void analyzeInsts (size_t addr,size_t max_inst);
		
	};

}

#endif // R_X86FUNCTIONANALYZER_H
