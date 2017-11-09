#ifndef SSAPHINODEGENERATOR_H
#define SSAPHINODEGENERATOR_H

#include "SSATransformer.h"
#include "General.h"
#include "Architecture.h"

namespace holodec {

	struct SSARegDef{
		HId ssaId;
		HId regId, parentId;
		uint64_t offset, size;
	};
	struct SSAMemDef{
		HId ssaId;
		HId memId;
	};
	
	struct BasicBlockWrapper{
		SSABB* ssaBB;
		
		HList<SSARegDef> inputs;
		HList<SSARegDef> outputs;
		
		HList<SSAMemDef> inputMems;
		HList<SSAMemDef> outputMems;
		
		void print(Architecture* arch);
	};
	
	struct SSAPhiNodeGenerator : public SSATransformer {
		
		Function* function;
		
		HList<BasicBlockWrapper> bbwrappers;
		
		virtual void doTransformation (Function* function);
		
		void resolveRegs();
		
		void handleBBs(BasicBlockWrapper* wrapper, Register* reg,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount);
		void handleBBs(BasicBlockWrapper* wrapper, Memory* mem,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount);
		
		BasicBlockWrapper* getWrapper(HId id){
			for(BasicBlockWrapper& wrapper : bbwrappers){
				if(wrapper.ssaBB->id == id)
					return &wrapper;
			}
			return nullptr;
		}
		
		void getDominator();
	};

}

#endif // SSAPHINODEGENERATOR_H
