#ifndef H_X86FUNCTIONANALYZEH_H
#define H_X86FUNCTIONANALYZEH_H

#include "HFunctionAnalyzer.h"
#include "HGeneral.h"

#include <capstone.h>
#include "HArchitecture.h"

namespace holox86 {

	using namespace holodec;

	extern HArchitecture x86architecture;

	class Hx86FunctionAnalyzer : public HFunctionAnalyzer {
	private:
		csh handle;

		void setJumpDest (HInstruction* instruction);
		void analyzeInstruction (HInstruction* instr, size_t addr, cs_insn *insn);
		void setOperands (HInstruction* instruction, cs_detail* csdetail);
	public:
		Hx86FunctionAnalyzer (HArchitecture* arch);
		~Hx86FunctionAnalyzer();

		virtual bool canAnalyze (HBinary* binary);

		virtual bool init (HBinary* binary);
		virtual bool terminate();

		virtual void analyzeInsts (size_t addr);

	};
}

#endif // H_X86FUNCTIONANALYZEH_H
