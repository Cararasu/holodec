#include "RFunctionAnalyzer.h"

holodec::RFunctionAnalyzer::RFunctionAnalyzer (RArchitecture* arch) : binary (0), arch (arch) {
}

holodec::RFunctionAnalyzer::~RFunctionAnalyzer() {
}

bool holodec::RFunctionAnalyzer::postInstruction (RInstruction* instruction) {
	instructionList.push_back (*instruction);
	if (instruction->instrdef) {
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
	printf("Post BB 0x%X\n",basicblock->addr);
	RInstruction& i = basicblock->instructions.back();
	if (i.instrdef && (i.instrdef->type == R_INSTR_TYPE_JMP || i.instrdef->type2 == R_INSTR_TYPE_JMP)) {
		if (i.condition != R_INSTR_COND_FALSE && i.jumpdest)
			registerBasicBlock (i.jumpdest);
		if (i.condition != R_INSTR_COND_TRUE && i.nojumpdest)
			registerBasicBlock (i.nojumpdest);
	}
	bbList.push_back (*basicblock);
}

bool holodec::RFunctionAnalyzer::registerBasicBlock (size_t addr) {
	printf("Register BB To Analyze 0x%X\n",addr);
	for (RBasicBlock& basicblock : bbList) {
		if (basicblock.addr == addr)
			return true;
		if (addr >= basicblock.addr && addr < (basicblock.addr + basicblock.size))
			continue;
		if (!splitBasicBlock (&basicblock, addr))
			return true;
	}
	addrToAnalyze.push_back (addr);
	return true;
}
bool holodec::RFunctionAnalyzer::splitBasicBlock (RBasicBlock* basicblock, size_t splitaddr) {
	for (auto instrit = basicblock->instructions.begin(); instrit != basicblock->instructions.end(); instrit++) {
		RInstruction& instruction = *instrit;
		if (splitaddr == instruction.addr) {
			printf("Split BB 0x%X\n",splitaddr);
			RBasicBlock newbb = {RList<RInstruction> (basicblock->instructions.begin(), instrit), 0, 0, R_INSTR_COND_TRUE, basicblock->addr, (instruction.addr + instruction.size) - basicblock->addr};
			basicblock->size = basicblock->size - newbb.size;
			basicblock->addr = instruction.addr;
			basicblock->instructions.erase (basicblock->instructions.begin(), instrit);
			bbList.push_back (newbb);
			return true;
		}
	}
	return false;
}

bool holodec::RFunctionAnalyzer::postFunction (RFunction* function) {
	printf("Post Function\n");
	binary->addFunction (function);
}

void holodec::RFunctionAnalyzer::preAnalysis() {
	printf("Pre Analysis\n");
}
void holodec::RFunctionAnalyzer::postAnalysis() {
	printf("Post Analysis\n");
}

void holodec::RFunctionAnalyzer::analyzeFunction (RSymbol* functionsymbol) {
	addrToAnalyze.clear();
	
	preAnalysis();
	
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
			instructionList.clear();
		}
	}
	
	postAnalysis();
}


holodec::RList<holodec::RFunction*> holodec::RFunctionAnalyzer::analyzeFunctions (holodec::RList<RSymbol*>* functionsymbols) {
	return holodec::RList<holodec::RFunction*> (0);
}
