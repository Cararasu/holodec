#ifndef H_X86FUNCTIONANALYZEH_H
#define H_X86FUNCTIONANALYZEH_H

#include "../../FunctionAnalyzer.h"
#include "../../General.h"

#include <capstone.h>
#include "../../Architecture.h"

namespace holox86 {

	using namespace holodec;

	extern Architecture x86architecture;

	class X86FunctionAnalyzer : public FunctionAnalyzer {
	private:
		csh handle;

		void setJumpDest (Instruction* instruction);
		void analyzeInstruction (Instruction* instr, size_t addr, cs_insn *insn);
		void setOperands (Instruction* instruction, cs_detail* csdetail);
	public:
		X86FunctionAnalyzer (Architecture* arch);
		~X86FunctionAnalyzer();

		virtual bool canAnalyze (Binary* binary);

		virtual bool init (Binary* binary);
		virtual bool terminate();

		virtual bool analyzeInsts (size_t addr);

	};
	
	#define CUSOM_X86_INSTR_EXTR_REP 	(0x1000000)
	#define CUSOM_X86_INSTR_EXTR_REPE 	CUSOM_X86_INSTR_EXTR_REP
	#define CUSOM_X86_INSTR_EXTR_REPNE 	(0x2000000)
}

#endif // H_X86FUNCTIONANALYZEH_H
