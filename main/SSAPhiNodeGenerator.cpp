#include "SSAPhiNodeGenerator.h"
#include "Function.h"
#include "Architecture.h"
#include <assert.h>

namespace holodec {


	void setSSAArg(SSARepresentation* ssaRep, SSAExpression* expr, HId argIndex, SSAArgument arg) {
		if (arg.ssaId == 338)
			printf("");
		expr->subExpressions[argIndex].replace(arg);
	}

	void BasicBlockWrapper::print (Architecture* arch) {
		printf ("BB %d\n", ssaBB->id);
		printf ("Address 0x%" PRIx64 " - 0x%" PRIx64 "\n", ssaBB->startaddr, ssaBB->endaddr);
		printf ("Fallthrough %d\n", ssaBB->fallthroughId);

		printf ("InBlocks ");
		for (HId id : ssaBB->inBlocks) {
			printf ("%d, ", id);
		}
		printf ("\n");
		printf ("OutBlocks ");
		for (HId id : ssaBB->outBlocks) {
			printf ("%d, ", id);
		}
		printf ("\n");

		printf ("Outputs ");
		for (SSARegDef& def : outputs) {
			printf ("%s, ", arch->getRegister (def.regId)->name.cstr());
		}
		printf ("\n");
	}


	void SSAPhiNodeGenerator::addRegDef(HId id, Register* reg, HList<SSARegDef>* list, bool replace) {
		bool rep = false;
		int i = 0;
		for (auto it = list->begin(); it != list->end();) {
			if(id == 0xa4)
				i++;
			if (it->regId == reg->id || (replace && it->parentId == reg->parentRef.refId && (reg->offset <= it->offset && (it->offset + it->size) <= (reg->offset + reg->size)))) {
				if (rep) {
					it = list->erase (it);
					continue;
				} else {
					*it = {id, reg->id, reg->parentRef.refId, reg->offset, reg->size};
					rep = true;
				}
			}
			++it;
		}
		if (!rep)
			list->push_back ({id, reg->id, reg->parentRef.refId, reg->offset, reg->size});

	}

	SSAArgument SSAPhiNodeGenerator::getSSAId(BasicBlockWrapper* wrapper, Register* reg) {

		while (true) {

			for (SSARegDef& def : wrapper->outputs) {
				if (def.regId == reg->id) {
					return SSAArgument::createId(def.ssaId, reg->size);
					break;
				}
			}
			for (SSARegDef& def : wrapper->outputs) {
				if ((def.parentId == (HId)reg->parentRef) && ((def.offset <= reg->offset) && ((reg->offset + reg->size) <= (def.offset + def.size)))) {
					return SSAArgument::createReg(reg, def.ssaId, reg->offset - def.offset);
				}
			}
			if (wrapper->ssaBB->inBlocks.size() != 1)
				break;
			wrapper = getWrapper(wrapper->ssaBB->inBlocks[0]);
		}
		assert(wrapper->ssaBB->inBlocks.size() > 1);

		SSAExpression phinode;
		phinode.type = SSAExprType::ePhi;
		phinode.exprtype = SSAType::eUInt;
		phinode.location = SSALocation::eReg;
		phinode.locref = { reg->id, 0 };
		phinode.size = reg->size;
		phinode.instrAddr = wrapper->ssaBB->startaddr;
		HId id = function->ssaRep.addAtStart(&phinode, wrapper->ssaBB);
		addRegDef(id, reg, &wrapper->outputs, false);
		for (HId bbId : wrapper->ssaBB->inBlocks) {
			//expressions need to reloaded after each call to getSSAId as they may insert an expression
			function->ssaRep.expressions[id].subExpressions.push_back(SSAArgument::createBlock(bbId));
			function->ssaRep.expressions[id].subExpressions.push_back(getSSAId(getWrapper(bbId), reg));
		}
		return SSAArgument::createReg(reg, id);
	}
	SSAArgument SSAPhiNodeGenerator::getSSAId(BasicBlockWrapper* wrapper, HList<SSARegDef>& defs, Register* reg) {

		for (SSARegDef& def : defs) {
			if (def.regId == reg->id) {
				return SSAArgument::createId(def.ssaId, reg->size);
			}
		}
		for (SSARegDef& def : defs) {
			if ((def.parentId == (HId)reg->parentRef) && ((def.offset <= reg->offset) && ((reg->offset + reg->size) <= (def.offset + def.size)))) {
				return SSAArgument::createReg(reg, def.ssaId, reg->offset - def.offset);
			}
		}
		if (wrapper->ssaBB->inBlocks.size() == 1) {
			return getSSAId(getWrapper(wrapper->ssaBB->inBlocks[0]), reg);
		}

		assert(wrapper->ssaBB->inBlocks.size() > 1);

		SSAExpression phinode;
		phinode.type = SSAExprType::ePhi;
		phinode.exprtype = SSAType::eUInt;
		phinode.location = SSALocation::eReg;
		phinode.locref = { reg->id, 0 };
		phinode.size = reg->size;
		phinode.instrAddr = wrapper->ssaBB->startaddr;
		HId id = function->ssaRep.addAtStart(&phinode, wrapper->ssaBB);
		addRegDef(id, reg, &defs, false);
		bool contains = false;
		for (SSARegDef& def : wrapper->outputs) {
			if (def.regId == reg->id || ((def.parentId == (HId)reg->parentRef) && ((def.offset <= reg->offset) && ((reg->offset + reg->size) <= (def.offset + def.size))))) {
				contains = true;
				break;
			}
		}
		if (!contains) {
			addRegDef(id, reg, &wrapper->outputs, false);
		}
		for (HId bbId : wrapper->ssaBB->inBlocks) {
			//expressions need to reloaded after each call to getSSAId as they may insert an expression
			function->ssaRep.expressions[id].subExpressions.push_back(SSAArgument::createBlock(bbId));
			function->ssaRep.expressions[id].subExpressions.push_back(getSSAId(getWrapper(bbId), reg));
		}
		return SSAArgument::createReg(reg, id);
	}

	void SSAPhiNodeGenerator::doTransformation (Binary* binary, Function* function) {

		printf ("Generating Phi-Nodes for Function at Address 0x%" PRIx64 "\n", function->baseaddr);
		this->binary = binary;
		this->function = function;

		bbwrappers.clear();
		bbwrappers.resize(function->ssaRep.bbs.size());
		for (size_t i = 0; i < function->ssaRep.bbs.list.size(); i++) {
			bbwrappers[i].ssaBB = &function->ssaRep.bbs.list[i];
		}
		for (BasicBlockWrapper& bbwrapper : bbwrappers) {//iterate Blocks
			for (size_t j = 0; j < bbwrapper.ssaBB->exprIds.size(); j++) {//iterate Expressions
				HId id = bbwrapper.ssaBB->exprIds[j];
				SSAExpression* expr = function->ssaRep.expressions.get(id);
				switch (expr->location) {
				case SSALocation::eReg:
					addRegDef(expr->id, arch->getRegister(expr->locref.refId), &bbwrapper.outputs, !EXPR_IS_TRANSPARENT(expr->type));
					break;
				default:
					break;
				}
			}
		}

		for (BasicBlockWrapper& bbwrapper : bbwrappers) {//iterate Blocks

			HList<SSARegDef> defs;
			for (size_t j = 0; j < bbwrapper.ssaBB->exprIds.size(); j++) {//iterate Expressions
				HId id = bbwrapper.ssaBB->exprIds[j];
				SSAExpression* expr = function->ssaRep.expressions.get(id);
				for (size_t i = 0; i < expr->subExpressions.size(); i++) {
					if (expr->subExpressions[i].type != SSAArgType::eId || expr->subExpressions[i].ssaId)
						continue;
					if (expr->subExpressions[i].location != SSALocation::eReg)
						assert(false);

					Register* reg = arch->getRegister(expr->subExpressions[i].locref.refId);
					assert(reg->id);
					SSAArgument anArg = getSSAId(&bbwrapper, defs, reg);
					assert(anArg.ssaId);
					expr = function->ssaRep.expressions.get(id);//reload Expression
					expr->subExpressions[i].replace(anArg);
					continue;
				}
				switch (expr->location) {
				case SSALocation::eReg:
					addRegDef(expr->id, arch->getRegister(expr->locref.refId), &defs, !EXPR_IS_TRANSPARENT(expr->type));
					break;
				default:
					break;
				}
			}
		}
		for (size_t i = 0; i < function->ssaRep.bbs.list.size(); i++) {
			bbwrappers[i].print(binary->arch);
		}
		function->print(binary->arch);
		function->ssaRep.compress();
	}

	bool SSAPhiNodeGenerator::handleBBs (BasicBlockWrapper* wrapper, Register* reg,  std::vector<std::pair<HId, HId>>& gatheredIds, std::vector<HId>& visitedBlocks) {
		//printf ("\nHandling Block %d\n", wrapper->ssaBB->id);

		SSARegDef* foundParentDef = nullptr;
		for (SSARegDef& regDef : wrapper->outputs) {
			if (regDef.parentId == reg->parentRef.refId) {
				if (regDef.regId == reg->id) {
					gatheredIds.push_back(std::make_pair(wrapper->ssaBB->id,regDef.ssaId));
					//printf ("\Found perfect Match %d\n", regDef.ssaId);
					return true;
				} else if (regDef.regId == reg->parentRef.refId) {
					//printf ("\Found parent Match %d\n", regDef.ssaId);
					foundParentDef = &regDef;
				}
			}
		}
		if (foundParentDef) {
			//printf("Found parent Match %d\n", foundParentDef->ssaId);
			SSAExpression expr;
			expr.type = SSAExprType::eAssign;
			expr.exprtype = SSAType::eUInt;
			expr.size = reg->size;
			expr.location = SSALocation::eReg;
			expr.locref = {reg->id, 0};
			expr.subExpressions = {
				SSAArgument::createReg({foundParentDef->regId, 0}, reg->size, reg->offset, foundParentDef->ssaId)
			};
			bool found = false;
			for (auto it = wrapper->ssaBB->exprIds.begin(); it != wrapper->ssaBB->exprIds.end(); ++it) {
				if (foundParentDef->ssaId == *it) {
					expr.instrAddr = function->ssaRep.expressions[foundParentDef->ssaId].instrAddr;

					HId exprId = *function->ssaRep.addAfter (&expr, wrapper->ssaBB->exprIds, it);
					addRegDef (exprId, reg, &wrapper->outputs, false);
					gatheredIds.push_back(std::make_pair(wrapper->ssaBB->id, exprId));
					found = true;
					break;
				}
			}
			return found;
		} else {
			//printf("Found no match on BB %d\n", wrapper->ssaBB->id);
			for (HId visited : visitedBlocks) {
				if (visited == wrapper->ssaBB->id) {
					//printf("Already Visited BB %d\n", wrapper->ssaBB->id);
					return true;
				}
			}
			visitedBlocks.push_back(wrapper->ssaBB->id);

			bool handled = true;
			for (HId inBlockId : wrapper->ssaBB->inBlocks) {
				if (!handleBBs(getWrapper(inBlockId), reg, gatheredIds, visitedBlocks)) {
					handled = false;
				}
			}
			return handled;
		}
	}
	/*
	void SSAPhiNodeGenerator::handleBBs (BasicBlockWrapper* wrapper, Memory* mem,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount) {
		//printf("\nHandling Block %d\n", wrapper->ssaBB->id);

		//printf("Found no match on BB %d\n", wrapper->ssaBB->id);

		SSAMemDef* foundDef = nullptr;
		for (SSAMemDef& memDef : wrapper->outputMems) {
			if (memDef.memId == mem->id) {
				gatheredIds[ (*gatheredIdCount)++] = memDef.ssaId;
				return;
			}
		}
		for (int i = 0; i < *visitedBlockCount; i++) {
			if (visitedBlocks[i] == wrapper->ssaBB->id) {
				//printf("Already Visited BB %d\n", wrapper->ssaBB->id);
				return;
			}
		}
		visitedBlocks[ (*visitedBlockCount)++] = wrapper->ssaBB->id;

		for (HId inBlockId : wrapper->ssaBB->inBlocks) {
			handleBBs (getWrapper (inBlockId), mem, gatheredIds, gatheredIdCount, visitedBlocks, visitedBlockCount);
		}
	}*/

}
