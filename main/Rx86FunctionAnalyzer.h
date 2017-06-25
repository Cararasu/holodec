#ifndef R_X86FUNCTIONANALYZER_H
#define R_X86FUNCTIONANALYZER_H

#include "RFunctionAnalyzer.h"
#include "RGeneral.h"

#include <capstone.h>
#include "RArchitecture.h"

namespace holox86 {
	
	using namespace holodec;
	
	extern RArchitecture x86architecture;

	class Rx86FunctionAnalyzer : public RFunctionAnalyzer {
	private:
		csh handle;
		
		void setJumpDest (RInstruction* instruction);
		void analyzeInstruction (RInstruction* instr, size_t addr, cs_insn *insn);
		void setOperands (RInstruction* instruction, cs_detail* csdetail);
	public:
		Rx86FunctionAnalyzer(RArchitecture* arch);
		~Rx86FunctionAnalyzer();

		virtual bool canAnalyze (RBinary* binary);
		
		virtual bool init (RBinary* binary);
		virtual bool terminate();
		
		virtual void analyzeInsts (size_t addr,size_t max_inst);
		
	};

}

#endif // R_X86FUNCTIONANALYZER_H
