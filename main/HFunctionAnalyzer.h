#ifndef H_FUNCTIONANALYZEH_H
#define H_FUNCTIONANALYZEH_H

#include "HSection.h"
#include "HFunction.h"
#include "HGeneral.h"
#include <algorithm>
#include "HSSAGen.h"

namespace holodec {

#define H_FUNC_ANAL_BUFFERSIZE (128)
	class HArchitecture;
	class HBinary;

	struct HFunctionAnalyzer {
		HArchitecture* arch;
		HBinary* binary;
		HSSAGen ssaGen;
		
		bool analyzeWithIR = true;

		struct {
			uint8_t dataBuffer[H_FUNC_ANAL_BUFFERSIZE];
			size_t bufferSize;
			size_t maxInstr;
			HList<HInstruction> instructions;
			HFunction* function;

			void reset() {
				bufferSize = 0;
				maxInstr = 0;
				instructions.clear();
				function = nullptr;
			}
		} state;

		HFunctionAnalyzer (HArchitecture* arch);
		virtual ~HFunctionAnalyzer();

		virtual bool canAnalyze (HBinary* binary) = 0;

		virtual bool init (HBinary* binary) = 0;
		virtual bool terminate() = 0;

		virtual HList<HFunction*> analyzeFunctions (HList<HSymbol*>* functionsymbols);


		void prepareBuffer (uint64_t addr);
		bool postInstruction (HInstruction* instruction);
		bool postBasicBlock (HBasicBlock* basicblock);
		bool changedBasicBlock (HBasicBlock* basicblock);
		//is triggered at the end of basic blocks
		bool registerBasicBlock (uint64_t addr);
		bool splitBasicBlock (HBasicBlock* basicblock, uint64_t splitaddr);
		bool trySplitBasicBlock (uint64_t splitaddr);
		void addAddressToAnalyze(uint64_t addr);

		virtual void preAnalysis();

		virtual HId analyzeFunction (HSymbol* functionsymbol);
		virtual void analyzeFunction (HFunction* function);
		virtual void analyzeInsts (uint64_t addr) = 0;

		virtual void postAnalysis();
	};


}

#endif // H_FUNCTIONANALYZEH_H
