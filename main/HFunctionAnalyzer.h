#ifndef H_FUNCTIONANALYZEH_H
#define H_FUNCTIONANALYZEH_H

#include "HSection.h"
#include "HFunction.h"
#include "HGeneral.h"
#include <algorithm>
#include "HSSAGen.h"

namespace holodec {

#define HFUNCANAL_BUFFERSIZE (128)
	class HArchitecture;
	class HBinary;

	struct HFunctionAnalyzer {
		HArchitecture* arch;
		HBinary* binary;
		HSSAGen ssaGen;

		struct {
			uint8_t dataBuffer[HFUNCANAL_BUFFERSIZE];
			size_t bufferSize;
			size_t maxInstr;
			HList<size_t> addrToAnalyze;
			HFunction function;
			HList<HInstruction> instructions;

			void reset() {
				bufferSize = 0;
				maxInstr = 0;
				addrToAnalyze.clear();
				function.clear();
				instructions.clear();
			}
		} state;

		HFunctionAnalyzer (HArchitecture* arch);
		virtual ~HFunctionAnalyzer();

		virtual bool canAnalyze (HBinary* binary) = 0;

		virtual bool init (HBinary* binary) = 0;
		virtual bool terminate() = 0;

		virtual HList<HFunction*> analyzeFunctions (HList<HSymbol*>* functionsymbols);


		void prepareBuffer (size_t addr);
		bool postInstruction (HInstruction* instruction);
		bool postBasicBlock (HBasicBlock* basicblock);
		bool changedBasicBlock (HBasicBlock* basicblock);
		//is triggered at the end of basic blocks
		bool registerBasicBlock (size_t addr);
		bool splitBasicBlock (HBasicBlock* basicblock, size_t splitaddr);
		bool trySplitBasicBlock (size_t splitaddr);
		bool postFunction (HFunction* function);

		virtual void preAnalysis();

		virtual void analyzeFunction (HSymbol* functionsymbol);
		virtual void analyzeInsts (size_t addr) = 0;

		virtual void postAnalysis();
	};


}

#endif // H_FUNCTIONANALYZEH_H
