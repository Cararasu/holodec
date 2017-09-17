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
		HInstruction* instruction;

		HId activeBlockId = 0;
		HId lastOp = 0;
		bool endOfBlock = false;

		HSSABB* activeblock = nullptr;

		HSSARepresentation* ssaRepresentation = nullptr;

		HList<HSSATmpDef> tmpdefs;

		HSSAGen (HArchitecture* arch);
		~HSSAGen();

		void reset();
		void setup(HSSARepresentation* ssaReg);
		void setupForInstr();

		HId splitBasicBlock (uint64_t addr);

		HArgument replaceArg (HArgument arg);
		void insertLabel (uint64_t address, HId instructionId = 0);
		HId addExpression (HSSAExpression* expression);
		HId createNewBlock ();
		HSSABB* getBlock (HId blockId);
		HSSABB* getActiveBlock ();
		void setActiveBlock ();
		void activateBlock (HId block);

		HIRRepresentation* matchIr (HInstruction* instr);

		template<typename ARGLIST>
		HArgument parseConstExpression (HArgument argExpr, ARGLIST* arglist);

		HArgument parseExpression (HArgument exprId);

		void print (int indent = 0);
	};

}

#endif // HSSAGEN_H
