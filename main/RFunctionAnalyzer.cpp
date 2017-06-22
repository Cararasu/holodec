#include "RFunctionAnalyzer.h"

holodec::RFunctionAnalyzer::RFunctionAnalyzer() : binary (0) {
}

holodec::RFunctionAnalyzer::~RFunctionAnalyzer() {
}

bool holodec::RFunctionAnalyzer::postInstruction (RInstruction* instruction) {
	instructionList.push_back (*instruction);
	if(instruction->instrdef){
		switch (instruction->instrdef->type) {
		case R_INSTR_TYPE_JMP:
		case R_INSTR_TYPE_RET:
			return false;
		}
		switch (instruction->instrdef->type2) {
		case R_INSTR_TYPE_JMP:
		case R_INSTR_TYPE_RET:
			return false;
		}
		
	}
	return true;
}

bool holodec::RFunctionAnalyzer::postBasicBlock (RBasicBlock* basicblock) {
	RInstruction& i = basicblock->instructions.back();
	if(i.instrdef && (i.instrdef->type == R_INSTR_TYPE_JMP || i.instrdef->type2 == R_INSTR_TYPE_JMP) ){
		if (i.condition != R_INSTR_COND_FALSE && i.jumpdest)
			addrToAnalyze.push_back (i.jumpdest);
		if (i.condition != R_INSTR_COND_TRUE && i.nojumpdest)
			addrToAnalyze.push_back (i.nojumpdest);
	}
	bbList.push_back (*basicblock);
}

bool holodec::RFunctionAnalyzer::splitBasicBlock (RBasicBlock* basicblock, size_t splitaddr) {

}

bool holodec::RFunctionAnalyzer::postFunction (RFunction* function) {
	binary->addFunction (function);
}

void holodec::RFunctionAnalyzer::preAnalysis() {
}

void holodec::RFunctionAnalyzer::analyzeFunction (RSymbol* functionsymbol) {
	addrToAnalyze.clear();

	size_t addr = functionsymbol->vaddr;
	addrToAnalyze.push_back (addr);
	while (!addrToAnalyze.empty()) {
		addr = addrToAnalyze.back();
		addrToAnalyze.pop_back();
		analyzeInsts (addr);

		if (!instructionList.empty()) {
			RInstruction* firstI = &instructionList.front();
			RInstruction* lastI = &instructionList.back();
			size_t next1 = lastI->jumpdest;
			size_t next2 = lastI->nojumpdest;
			RBasicBlock basicblock = {instructionList, 0, 0, lastI->condition, firstI->addr, lastI->addr + lastI->size};
			basicblock.print();
			postBasicBlock (&basicblock);
		}
	}
}

void holodec::RFunctionAnalyzer::postAnalysis() {
}

holodec::RList<holodec::RFunction*> holodec::RFunctionAnalyzer::analyzeFunctions (holodec::RList<RSymbol*>* functionsymbols) {
	return holodec::RList<holodec::RFunction*> (0);
}
