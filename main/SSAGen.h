#ifndef SSAGEN_H
#define SSAGEN_H

#include "Function.h"

namespace holodec {

	class Architecture;

	struct SSATmpDef {
		HId id;
		IRArgument arg;
	};
	
	
	struct SSAGen {
		Architecture* arch;

		HList<IRArgument> arguments;
		Instruction* instruction = nullptr;

		HId activeBlockId = 0;
		HId lastOp = 0;
		bool endOfBlock = false;
		bool fallthrough = false;

		SSABB* activeblock = nullptr;

		Function* function = nullptr;
		SSARepresentation* ssaRepresentation = nullptr;

		HList<SSATmpDef> tmpdefs;

		SSAGen (Architecture* arch);
		~SSAGen();

		void reset();
		void setup(Function* function, uint64_t addr);
		void setupForInstr();

		HId splitBasicBlock (uint64_t addr);

		IRArgument parseMemArgToExpr(IRArgument mem);
		IRArgument replaceArg (IRArgument arg);
		SSAArgument parseIRArg2SSAArg(IRArgument arg);
		void insertLabel (uint64_t address, HId instructionId = 0);
		HId addExpression (SSAExpression* expression);
		HId createNewBlock ();
		SSABB* getBlock (HId blockId);
		SSABB* getActiveBlock ();
		void setActiveBlock ();
		void activateBlock (HId block);
		
		void addUpdateRegExpressions(HId regId, HId ssaId);

		IRRepresentation* matchIr (Instruction* instr);

		template<typename ARGLIST>
		IRArgument parseConstExpression (IRArgument argExpr, ARGLIST* arglist);
		

		bool parseInstruction (Instruction* instruction);
		IRArgument parseExpression (IRArgument exprId);

		void print (int indent = 0);
	};

}

#endif // SSAGEN_H
