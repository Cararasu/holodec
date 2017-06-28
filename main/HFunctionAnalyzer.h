#ifndef H_FUNCTIONANALYZEH_H
#define H_FUNCTIONANALYZEH_H

#include "HSection.h"
#include "HBinary.h"
#include "HFunction.h"
#include "HGeneral.h"
#include <algorithm>

namespace holodec {

#define HFUNCANAL_BUFFERSIZE (128)
	class HArchitecture;

	struct HFunctionAnalyzer {
		HArchitecture* arch;
		HBinary* binary;
		
		struct {
			uint8_t dataBuffer[HFUNCANAL_BUFFERSIZE];
			size_t bufferSize;
			size_t maxInstr;
			HList<size_t> addrToAnalyze;
			HList<HBasicBlock> bbs;
			HList<HInstruction> instructions;

			void reset() {
				bufferSize = 0;
				maxInstr = 0;
				addrToAnalyze.clear();
				bbs.clear();
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
		//is triggered at the end of basic blocks
		bool registerBasicBlock (size_t addr);
		bool splitBasicBlock (HBasicBlock* basicblock, size_t splitaddr);
		bool postFunction (HFunction* function);

		virtual void preAnalysis();

		virtual void analyzeFunction (HSymbol* functionsymbol);
		virtual void analyzeInsts (size_t addr) = 0;

		virtual void postAnalysis();
	};


}

#endif // H_FUNCTIONANALYZEH_H
