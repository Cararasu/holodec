#ifndef HSSAGEN_H
#define HSSAGEN_H

#include "HFunction.h"

namespace holodec {

	class HArchitecture;

	struct HSSAGenDef {
		HId id;
		uint64_t offset;
		uint64_t size;
		HSSAId ssaId;
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
		HIdGenerator idGen;
		
		HArchitecture* arch;
		
		HList<HSSAExpression> expressions;
		HList<HSSAGenRegDefs> regInputs;
		HList<HSSAGenRegDefs> regdefslist;
		HList<HSSAGenDef> tmpdefs;

		HSSAId getInputSSA (HRegister* reg);

		HSSAArg createSSARegDef (HRegister* reg);
		HSSAArg getSSARegUse (HRegister* reg);
		HSSAArg createSSATmpDef (HId index, uint64_t size);
		HSSAArg getSSATmpDef (HId index);
		void clearSSATmpDefs ();
		HSSAArg createSSAStckDef (HId id, HId index);
		HSSAArg getSSAStckDef (HId id, HId index);
	};

	struct HSSAGen {
		HArchitecture* arch;

		HIdList<HSSAGenBB> genBBs;

		HSSAGen (HArchitecture* arch);
		~HSSAGen();

		HIRRepresentation* matchIr (HInstruction* instr);

		HIRArg parseConstExpression (HIRArg argExpr, HInstruction* instr);

		void insertLabel(uint64_t address);
		
		void addExpression(HSSAExpression* expression);
		
		HSSAArg parseExpression (HIRArg exprId);
	};

}

#endif // HSSAGEN_H
