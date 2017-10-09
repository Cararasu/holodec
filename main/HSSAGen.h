#ifndef HSSAGEN_H
#define HSSAGEN_H

#include "HFunction.h"

namespace holodec {

	class HArchitecture;

	struct HSSATmpDef {
		HId id;
		HArgument arg;
	};
	
	
	struct HSSAGen {
		HArchitecture* arch;

		HList<HArgument> arguments;
		HInstruction* instruction = nullptr;

		HId activeBlockId = 0;
		HId lastOp = 0;
		bool endOfBlock = false;
		bool fallthrough = false;

		HSSABB* activeblock = nullptr;

		HSSARepresentation* ssaRepresentation = nullptr;

		HList<HSSATmpDef> tmpdefs;

		HSSAGen (HArchitecture* arch);
		~HSSAGen();

		void reset();
		void setup(HSSARepresentation* ssaReg, uint64_t addr);
		void setupForInstr();

		HId splitBasicBlock (uint64_t addr);

		HArgument parseMemArgToExpr(HArgument mem);
		HArgument replaceArg (HArgument arg);
		void insertLabel (uint64_t address, HId instructionId = 0);
		HId addExpression (HSSAExpression* expression);
		HId createNewBlock ();
		HSSABB* getBlock (HId blockId);
		HSSABB* getActiveBlock ();
		void setActiveBlock ();
		void activateBlock (HId block);
		
		void addUpdateRegExpressions(HId regId, HId exprId);

		HIRRepresentation* matchIr (HInstruction* instr);

		template<typename ARGLIST>
		HArgument parseConstExpression (HArgument argExpr, ARGLIST* arglist);
		

		bool parseInstruction (HInstruction* instruction);
		HArgument parseExpression (HArgument exprId);

		void print (int indent = 0);
	};

}

#endif // HSSAGEN_H
