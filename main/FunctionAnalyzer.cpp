#include "FunctionAnalyzer.h"
#include "Binary.h"
#include <assert.h>

holodec::FunctionAnalyzer::FunctionAnalyzer (Architecture* arch) : binary (0), arch (arch), ssaGen (arch) {
}

holodec::FunctionAnalyzer::~FunctionAnalyzer() {
}

void holodec::FunctionAnalyzer::prepareBuffer (uint64_t addr) {
	uint8_t* ptr = binary->getVDataPtr (addr);
	uint64_t size = binary->getVDataSize (addr);
	if (ptr) {
		state.bufferSize = std::min (size, (uint64_t) H_FUNC_ANAL_BUFFERSIZE);
		memcpy (state.dataBuffer, ptr, state.bufferSize);
	} else {
		state.bufferSize = 0;
	}
}
bool holodec::FunctionAnalyzer::postInstruction (Instruction* instruction) {
	/*if (state.function->findBasicBlockDeep (instruction->addr + instruction->size))
		return false;*/
	state.instructions.push_back (*instruction);
	if (analyzeWithIR && ssaGen.parseInstruction(instruction)) {
		if (ssaGen.endOfBlock) {
			if (instruction->jumpdest)
				addAddressToAnalyze (instruction->jumpdest);
			if (instruction->nojumpdest)
				addAddressToAnalyze (instruction->nojumpdest);
			return false;
		}
		return instruction->nojumpdest ? !trySplitBasicBlock(instruction->nojumpdest) : true;
	}

	if (instruction->instrdef->type == H_INSTR_TYPE_JMP || instruction->instrdef->type2 == H_INSTR_TYPE_JMP) {
		addAddressToAnalyze (instruction->jumpdest);
		return false;
	} else if (instruction->instrdef->type == H_INSTR_TYPE_CJMP || instruction->instrdef->type2 == H_INSTR_TYPE_CJMP) {
		addAddressToAnalyze (instruction->jumpdest);
		addAddressToAnalyze (instruction->nojumpdest);
		return false;
	}
	return instruction->nojumpdest ? !trySplitBasicBlock(instruction->nojumpdest) : true;
}

bool holodec::FunctionAnalyzer::postBasicBlock (HBasicBlock* basicblock) {
	state.function->addBasicBlock (*basicblock);
}

bool holodec::FunctionAnalyzer::changedBasicBlock (HBasicBlock* basicblock) {

}
bool holodec::FunctionAnalyzer::splitBasicBlock (HBasicBlock* basicblock, uint64_t splitaddr) {
	for (auto instrit = basicblock->instructions.begin(); instrit != basicblock->instructions.end(); instrit++) {
		Instruction& instruction = *instrit;
		if (splitaddr != instruction.addr)
			continue;
		
		HBasicBlock newbb = {
			0,
			HList<Instruction> (instrit, basicblock->instructions.end()),
			basicblock->nextblock,
			basicblock->nextcondblock,
			basicblock->jumptable,
			instruction.addr,
			(basicblock->addr + basicblock->size) - instruction.addr
		};
		basicblock->size = basicblock->size - newbb.size;
		basicblock->nextblock = 0;
		basicblock->nextcondblock = 0;
		basicblock->jumptable = 0;
		basicblock->instructions.erase (instrit, basicblock->instructions.end());
		changedBasicBlock (basicblock);
		this->postBasicBlock(&newbb);

		if (analyzeWithIR)
			assert (ssaGen.splitBasicBlock (splitaddr));
		return true;
	}
	return false;
}
bool holodec::FunctionAnalyzer::trySplitBasicBlock (uint64_t splitaddr) {
	for (HBasicBlock& basicblock : state.function->basicblocks) {
		if (basicblock.addr == splitaddr)
			return true;
		if (basicblock.addr <= splitaddr && splitaddr < (basicblock.addr + basicblock.size)){
			if (splitBasicBlock (&basicblock, splitaddr)) {
				return true;
			}
		}
	}
	return false;
}
void holodec::FunctionAnalyzer::addAddressToAnalyze (uint64_t addr) {
	if (std::find (state.function->addrToAnalyze.begin(), state.function->addrToAnalyze.end(), addr) == state.function->addrToAnalyze.end()) {
		printf ("Add Address for Analyze 0x%x\n", addr);
		state.function->addrToAnalyze.push_back (addr);
	}
}

void holodec::FunctionAnalyzer::preAnalysis() {
	printf ("Pre Analysis\n");
}
void holodec::FunctionAnalyzer::postAnalysis() {
	printf ("Post Analysis\n");
}

holodec::HId holodec::FunctionAnalyzer::analyzeFunction (Symbol* functionsymbol) {
	Function newfunction;
	newfunction.symbolref = functionsymbol->id;
	newfunction.baseaddr = functionsymbol->vaddr;
	newfunction.addrToAnalyze.push_back (functionsymbol->vaddr);
	if(!analyzeFunction (&newfunction)){
		return 0;
	}
	return binary->addFunction (newfunction);
}
bool holodec::FunctionAnalyzer::analyzeFunction (Function* function) {
	state.reset();
	state.function = function;
	Symbol* functionsymbol = binary->getSymbol (function->symbolref);
	printf ("Analyzing Function %s\n", functionsymbol->name.cstr());
	printf ("At Address 0x%x\n", functionsymbol->vaddr);

	preAnalysis();

	ssaGen.setup (&state.function->ssaRep, function->baseaddr);
	while (!state.function->addrToAnalyze.empty()) {
		uint64_t addr = state.function->addrToAnalyze.back();
		state.function->addrToAnalyze.pop_back();

		if (trySplitBasicBlock (addr))
			continue;
		
		ssaGen.activateBlock (ssaGen.createNewBlock());
		
		if(!analyzeInsts (addr)){
			return false;
		}
		
		if (state.instructions.empty())
			continue;
			
		Instruction* firstI = &state.instructions.front();
		Instruction* lastI = &state.instructions.back();
		HBasicBlock basicblock = {0, state.instructions, 0, 0, 0, firstI->addr, (lastI->addr + lastI->size) - firstI->addr};
		postBasicBlock (&basicblock);
		state.instructions.clear();
	}
	for (SSABB& bb : state.function->ssaRep.bbs) {
		for (HId& id : bb.exprIds) {
			SSAExpression* expr = state.function->ssaRep.expressions.get (id);
			if (expr->type == SSA_EXPR_CALL) {
				assert (expr->subExpressions.size());
				if (expr->subExpressions[0].type == SSA_ARGTYPE_UINT) {
					printf ("Found Function 0x%x\n", expr->subExpressions[0].uval);
				}
			}
		}
	}
	postAnalysis();
	return true;
}


holodec::HList<holodec::Function*> holodec::FunctionAnalyzer::analyzeFunctions (holodec::HList<Symbol*>* functionsymbols) {
	return holodec::HList<holodec::Function*> (0);
}
