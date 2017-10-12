#ifndef HSSAPHINODEGENERATOR_H
#define HSSAPHINODEGENERATOR_H

#include "HSSATransformer.h"
#include "HGeneral.h"
#include "HArchitecture.h"

namespace holodec {

	struct HSSARegDef{
		HId ssaId;
		HId regId, parentId;
		uint64_t offset, size;
	};
	struct HSSAMemDef{
		HId ssaId;
		HId memId;
	};
	
	struct BasicBlockWrapper{
		HSSABB* ssaBB;
		
		HList<HId> inBlocks;
		HList<HId> outBlocks;
		
		HList<HSSARegDef> inputs;
		HList<HSSARegDef> outputs;
		
		HList<HSSAMemDef> inputMems;
		HList<HSSAMemDef> outputMems;
		
		void print(HArchitecture* arch);
	};
	
	struct HSSAPhiNodeGenerator : public HSSATransformer {
		
		HFunction* function;
		
		HList<BasicBlockWrapper> bbwrappers;
		
		virtual void doTransformation (HFunction* function);
		
		void resolveRegs();
		
		void handleBBs(BasicBlockWrapper* wrapper, HRegister* reg,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount);
		void handleBBs(BasicBlockWrapper* wrapper, HMemory* mem,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount);
		
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

#endif // HSSAPHINODEGENERATOR_H
