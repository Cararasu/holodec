#ifndef HSSAGEN_H
#define HSSAGEN_H

#include "HFunction.h"

namespace holodec {

	class HArchitecture;

	struct HSSAGenDef {
		HId id;
		uint64_t offset;
		uint64_t size;
		HArgument arg;
	};
	inline bool operator< (HSSAGenDef& lhs, HSSAGenDef& rhs) {
		return lhs.offset < rhs.offset;
	}
	struct HSSAGenRegDefs {
		HId id;
		bool cleared;
		HList<HSSAGenDef> defs;
	};
	struct HSSAGenBB {
		HId id;
		HId fallthroughId = 0;
		
		HArchitecture* arch;
		
		HList<HId> expressionIds;
		HList<HSSAGenRegDefs> regInputs;
		HList<HSSAGenRegDefs> regdefslist;

		HId getInputSSA (HRegister* reg);

		HArgument createSSARegDef (HRegister* reg);
		HArgument getSSARegUse (HRegister* reg);
		HArgument createSSATmpDef (HId index, uint64_t size);
		HArgument getSSATmpDef (HId index);
		void clearSSATmpDefs ();
		HArgument createSSAStckDef (HId id, HId index);
		HArgument getSSAStckDef (HId id, HId index);
	};

	struct HSSAGen {
		HArchitecture* arch;

		HId activeBlockId = 0;
		HId lastOp = 0;
		bool endOfBlock = false;
		bool fallthrough = true;
		
		HSSAGenBB* activeblock = nullptr;
		
		HIdList<HSSAGenBB> genBBs;
		HIdList<HSSAExpression> expressions;
		
		HList<uint64_t> addressesToAnalyze;
		
		HList<HSSAGenDef> tmpdefs;
		HList<HArgument> arguments;

		HSSAGen (HArchitecture* arch);
		~HSSAGen();

		void clear(){
			addressesToAnalyze.clear();
			expressions.clear();
			genBBs.clear();
			setupForInstr();
		}
		void setupForInstr(){
			endOfBlock = false;
			fallthrough = false;
			arguments.clear();
			tmpdefs.clear();
			addressesToAnalyze.clear();
		}
		HArgument replaceArg (HArgument arg);
		void insertLabel (uint64_t address, HId instructionId = 0);
		HId addExpression (HSSAExpression* expression);
		HId createNewBlock ();
		HSSAGenBB* getBlock (HId blockId);
		HSSAGenBB* getActiveBlock ();
		void setActiveBlock ();
		void activateBlock (HId block);
	
		HIRRepresentation* matchIr (HInstruction* instr);

		HArgument parseConstExpression (HArgument argExpr, HInstruction* instr);
		
		HArgument parseExpression (HArgument exprId);
		
		void print(int indent = 0);
	};

}

#endif // HSSAGEN_H
