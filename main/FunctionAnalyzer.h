#ifndef FUNCTIONANALYZER_H
#define FUNCTIONANALYZER_H

#include "Section.h"
#include "Function.h"
#include "General.h"
#include <algorithm>
#include "SSAGen.h"

namespace holodec {

#define H_FUNC_ANAL_BUFFERSIZE (128)
	struct Architecture;
	struct Binary;

	struct FunctionAnalyzer {
		Architecture* arch;
		Binary* binary;
		SSAGen ssaGen;
		
		bool analyzeWithIR = true;

		struct {
			size_t maxInstr;
			HList<Instruction> instructions;
			Function* function;

			void reset() {
				maxInstr = 0;
				instructions.clear();
				function = nullptr;
			}
		} state;

		FunctionAnalyzer (Architecture* arch);
		virtual ~FunctionAnalyzer();

		virtual bool canAnalyze (Binary* binary) = 0;

		virtual bool init (Binary* binary) = 0;
		virtual bool terminate() = 0;

		virtual HList<Function*> analyzeFunctions (HList<Symbol*>* functionsymbols);


		bool postInstruction (Instruction* instruction);
		bool postBasicBlock (DisAsmBasicBlock* basicblock);
		bool changedBasicBlock (DisAsmBasicBlock* basicblock);
		//is triggered at the end of basic blocks
		bool registerBasicBlock (uint64_t addr);
		bool splitBasicBlock (DisAsmBasicBlock* basicblock, uint64_t splitaddr);
		bool trySplitBasicBlock (uint64_t splitaddr);
		void addAddressToAnalyze(uint64_t addr);

		virtual void preAnalysis();

		virtual bool analyzeFunction (Function* function);
		virtual bool analyzeInsts (uint64_t addr) = 0;

		virtual void postAnalysis();
	};


}

#endif // FUNCTIONANALYZER_H
