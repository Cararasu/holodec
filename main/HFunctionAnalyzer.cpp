#include "HFunctionAnalyzer.h"
#include "HBinary.h"
#include <assert.h>

holodec::HFunctionAnalyzer::HFunctionAnalyzer (HArchitecture* arch) : binary (0), arch (arch), ssaGen (arch) {
}

holodec::HFunctionAnalyzer::~HFunctionAnalyzer() {
}

void holodec::HFunctionAnalyzer::prepareBuffer (uint64_t addr) {
	uint8_t* ptr = binary->getVDataPtr (addr);
	uint64_t size = binary->getVDataSize (addr);
	if (ptr) {
		state.bufferSize = std::min (size, (uint64_t) H_FUNC_ANAL_BUFFERSIZE);
		memcpy (state.dataBuffer, ptr, state.bufferSize);
	} else {
		state.bufferSize = 0;
	}
}
bool holodec::HFunctionAnalyzer::postInstruction (HInstruction* instruction) {
	/*if (state.function->findBasicBlockDeep (instruction->addr + instruction->size))
		return false;*/

	state.instructions.push_back (*instruction);
	if (analyzeWithIR) {
		HIRRepresentation* rep = ssaGen.matchIr (instruction);
		if (rep) {
			ssaGen.setupForInstr();
			ssaGen.instruction = instruction;
			for (int i = 0; i < instruction->operands.size(); i++) {
				ssaGen.arguments.push_back (instruction->operands[i]);
			}
			ssaGen.insertLabel (instruction->addr);
			
			ssaGen.parseExpression (rep->rootExpr);
			if (ssaGen.endOfBlock) {
				if (instruction->nojumpdest)
					addAddressToAnalyze (instruction->nojumpdest);
				if (instruction->jumpdest)
					addAddressToAnalyze (instruction->jumpdest);
				return false;
			}
			return true;
		} else {
			printf ("Could not find IR-Match for Instruction\n");
			instruction->print (arch);
		}
	}

	if (instruction->instrdef->type == H_INSTR_TYPE_JMP || instruction->instrdef->type2 == H_INSTR_TYPE_JMP) {
		addAddressToAnalyze (instruction->jumpdest);
		return false;
	} else if (instruction->instrdef->type == H_INSTR_TYPE_CJMP || instruction->instrdef->type2 == H_INSTR_TYPE_CJMP) {
		addAddressToAnalyze (instruction->jumpdest);
		addAddressToAnalyze (instruction->nojumpdest);
		return false;
	}
	return true;
}

bool holodec::HFunctionAnalyzer::postBasicBlock (HBasicBlock* basicblock) {
	state.function->addBasicBlock (*basicblock);
}

bool holodec::HFunctionAnalyzer::changedBasicBlock (HBasicBlock* basicblock) {

}
bool holodec::HFunctionAnalyzer::splitBasicBlock (HBasicBlock* basicblock, uint64_t splitaddr) {
	for (auto instrit = basicblock->instructions.begin(); instrit != basicblock->instructions.end(); instrit++) {
		HInstruction& instruction = *instrit;
		if (splitaddr == instruction.addr) {
			auto it = instrit;
			HBasicBlock newbb = {
				0,
				HList<HInstruction> (it, basicblock->instructions.end()),
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
			basicblock->instructions.erase (it, basicblock->instructions.end());
			changedBasicBlock (basicblock);
			this->postBasicBlock(&newbb);

			if (analyzeWithIR)
				assert (ssaGen.splitBasicBlock (splitaddr));
			return true;
		}
	}
	return false;
}
bool holodec::HFunctionAnalyzer::trySplitBasicBlock (uint64_t splitaddr) {
	for (HBasicBlock& basicblock : state.function->basicblocks) {
		if (basicblock.addr == splitaddr)
			return true;
		if (basicblock.addr <= splitaddr && splitaddr < (basicblock.addr + basicblock.size))
			if (splitBasicBlock (&basicblock, splitaddr)) {
				return true;
			}
	}
	return false;
}
void holodec::HFunctionAnalyzer::addAddressToAnalyze (uint64_t addr) {
	if (std::find (state.function->addrToAnalyze.begin(), state.function->addrToAnalyze.end(), addr) == state.function->addrToAnalyze.end()) {
		printf ("Add Address for Analyze 0x%x\n", addr);
		state.function->addrToAnalyze.push_back (addr);
	}
}

void holodec::HFunctionAnalyzer::preAnalysis() {
	printf ("Pre Analysis\n");
}
void holodec::HFunctionAnalyzer::postAnalysis() {
	printf ("Post Analysis\n");
}

holodec::HId holodec::HFunctionAnalyzer::analyzeFunction (HSymbol* functionsymbol) {
	HFunction newfunction;
	HId id = binary->addFunction (newfunction);
	HFunction* function = binary->getFunction (id);
	function->symbolref = functionsymbol->id;
	function->addrToAnalyze.push_back (functionsymbol->vaddr);
	analyzeFunction (function);
	return id;
}
void holodec::HFunctionAnalyzer::analyzeFunction (HFunction* function) {
	state.reset();
	state.function = function;
	HSymbol* functionsymbol = binary->getSymbol (function->symbolref);
	printf ("Analyzing Function %s\n", functionsymbol->name.cstr());
	printf ("At Address 0x%x\n", functionsymbol->vaddr);

	preAnalysis();

	ssaGen.setup (&state.function->ssaRep);
	while (!state.function->addrToAnalyze.empty()) {
		uint64_t addr = state.function->addrToAnalyze.back();
		state.function->addrToAnalyze.pop_back();

		if (trySplitBasicBlock (addr))
			continue;

		ssaGen.activateBlock (ssaGen.createNewBlock());
		analyzeInsts (addr);

		if (!state.instructions.empty()) {
			HInstruction* firstI = &state.instructions.front();
			HInstruction* lastI = &state.instructions.back();
			HBasicBlock basicblock = {0, state.instructions, 0, 0, 0, firstI->addr, (lastI->addr + lastI->size) - firstI->addr};
			postBasicBlock (&basicblock);
			state.instructions.clear();
		}
	}
	for (HSSABB& bb : state.function->ssaRep.bbs) {
		for (HId& id : bb.exprIds) {
			HSSAExpression* expr = state.function->ssaRep.expressions.get (id);
			if (expr->type == HSSA_EXPR_CALL) {
				assert (expr->subExpressions.size());
				if (expr->subExpressions[0].type == H_ARGTYPE_UINT) {
					printf ("Found Function 0x%x\n", expr->subExpressions[0].uval);
				}
			}
		}
	}
	postAnalysis();
}


holodec::HList<holodec::HFunction*> holodec::HFunctionAnalyzer::analyzeFunctions (holodec::HList<HSymbol*>* functionsymbols) {
	return holodec::HList<holodec::HFunction*> (0);
}
