#include "HFunctionAnalyzer.h"

holodec::HFunctionAnalyzer::HFunctionAnalyzer (HArchitecture* arch) : binary (0), arch (arch) {
}

holodec::HFunctionAnalyzer::~HFunctionAnalyzer() {
}

void holodec::HFunctionAnalyzer::prepareBuffer (size_t addr) {
	uint8_t* ptr = binary->getVDataPtr (addr);
	size_t size = binary->getVDataSize (addr);
	if (ptr) {
		state.bufferSize = std::min (size, (size_t) HFUNCANAL_BUFFERSIZE);
		memcpy (state.dataBuffer, ptr, state.bufferSize);
	} else {
		state.bufferSize = 0;
	}
}
bool holodec::HFunctionAnalyzer::postInstruction (HInstruction* instruction) {
	if(state.function.findBasicBlockDeep(instruction->addr + instruction->size))
		return false;

	state.instructions.push_back (*instruction);
	if (instruction->instrdef) {
		switch (instruction->instrdef->type) {
		case H_INSTR_TYPE_JMP:
		case H_INSTR_TYPE_RET:
			return false;
		}
		switch (instruction->instrdef->type2) {
		case H_INSTR_TYPE_JMP:
		case H_INSTR_TYPE_RET:
			return false;
		}

	}
	return true;
}

bool holodec::HFunctionAnalyzer::postBasicBlock (HBasicBlock* basicblock) {
	HInstruction& i = basicblock->instructions.back();
	if (i.instrdef && (i.instrdef->type == H_INSTR_TYPE_JMP || i.instrdef->type2 == H_INSTR_TYPE_JMP)) {
		if (i.condition != H_INSTR_COND_TRUE) {//if not default value then Instruction overwrites InstructionDefinition
			if (i.condition != H_INSTR_COND_FALSE && i.jumpdest)
				registerBasicBlock (i.jumpdest);
			if (i.condition != H_INSTR_COND_TRUE && i.nojumpdest)
				registerBasicBlock (i.nojumpdest);
		} else {
			if (i.instrdef->condition != H_INSTR_COND_FALSE && i.jumpdest)
				registerBasicBlock (i.jumpdest);
			if (i.instrdef->condition != H_INSTR_COND_TRUE && i.nojumpdest)
				registerBasicBlock (i.nojumpdest);
		}
	}
	state.function.addBasicBlock (*basicblock);
}

bool holodec::HFunctionAnalyzer::registerBasicBlock (size_t addr) {
	//TODO jump into current generated basic block
	state.addrToAnalyze.push_back (addr);
	return true;
}

bool holodec::HFunctionAnalyzer::changedBasicBlock (HBasicBlock* basicblock) {

}
bool holodec::HFunctionAnalyzer::splitBasicBlock (HBasicBlock* basicblock, size_t splitaddr) {
	for (auto instrit = basicblock->instructions.begin(); instrit != basicblock->instructions.end(); instrit++) {
		HInstruction& instruction = *instrit;
		if (splitaddr == instruction.addr) {
			auto it = instrit;
			HBasicBlock newbb = {
				0,
				HList<HInstruction> (it, basicblock->instructions.end()),
				basicblock->nextblock,
				basicblock->nextcondblock,
				basicblock->cond,
				instruction.addr,
				(basicblock->addr + basicblock->size) - instruction.addr
			};
			basicblock->size = basicblock->size - newbb.size;
			basicblock->cond = H_INSTR_COND_TRUE;
			basicblock->instructions.erase (it, basicblock->instructions.end());
			changedBasicBlock (basicblock);
			changedBasicBlock (&newbb);
			state.function.basicblocks.push_back (newbb);
			return true;
		}
	}
	return false;
}
bool holodec::HFunctionAnalyzer::trySplitBasicBlock (size_t splitaddr) {
	for (HBasicBlock& basicblock : state.function.basicblocks) {
		if (basicblock.addr == splitaddr)
			return true;
		if (basicblock.addr <= splitaddr && splitaddr < (basicblock.addr + basicblock.size))
			if (splitBasicBlock (&basicblock, splitaddr))
				return true;
	}
	return false;
}

bool holodec::HFunctionAnalyzer::postFunction (HFunction* function) {
	printf ("Post Function\n");
	binary->addFunction (*function);
	for (HBasicBlock& bb : function->basicblocks)
		bb.print();
}

void holodec::HFunctionAnalyzer::preAnalysis() {
	printf ("Pre Analysis\n");
}
void holodec::HFunctionAnalyzer::postAnalysis() {
	printf ("Post Analysis\n");
}

void holodec::HFunctionAnalyzer::analyzeFunction (HSymbol* functionsymbol) {

	state.reset();

	preAnalysis();
	printf ("Analyzing Function %s\n", functionsymbol->name.cstr());

	state.addrToAnalyze.push_back (functionsymbol->vaddr);
	while (!state.addrToAnalyze.empty()) {
		size_t addr = state.addrToAnalyze.back();
		state.addrToAnalyze.pop_back();

		if (trySplitBasicBlock (addr))
			continue;

		analyzeInsts (addr);

		if (!state.instructions.empty()) {
			HInstruction* firstI = &state.instructions.front();
			HInstruction* lastI = &state.instructions.back();
			HBasicBlock basicblock = {0, state.instructions, 0, 0, lastI->condition, firstI->addr, (lastI->addr + lastI->size) - firstI->addr};
			postBasicBlock (&basicblock);
			state.instructions.clear();
		}
	}
	for (HBasicBlock& bb : state.function.basicblocks) {
		HInstruction& i = bb.instructions.back();
		if (i.jumpdest) {
			HBasicBlock* foundbb = state.function.findBasicBlock (i.jumpdest);
			if (foundbb) {
				bb.nextcondblock = foundbb->id;
				printf ("Jump BB 0x%X to 0x%X true\n", bb.addr, foundbb->addr);
			}
		}
		if (i.nojumpdest) {
			HBasicBlock* foundbb = state.function.findBasicBlock (i.nojumpdest);
			if (foundbb) {
				bb.nextblock = foundbb->id;
				printf ("Jump BB 0x%X to 0x%X false\n", bb.addr, foundbb->addr);
			}
		}
	}
	binary->addFunction (state.function);
	state.function.clear();
	postAnalysis();
}


holodec::HList<holodec::HFunction*> holodec::HFunctionAnalyzer::analyzeFunctions (holodec::HList<HSymbol*>* functionsymbols) {
	return holodec::HList<holodec::HFunction*> (0);
}
