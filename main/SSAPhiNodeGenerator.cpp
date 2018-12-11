#include "SSAPhiNodeGenerator.h"
#include "Function.h"
#include "Architecture.h"
#include <assert.h>

namespace holodec {


	void setSSAArg(SSARepresentation* ssaRep, SSAExpression* expr, HId argIndex, SSAArgument arg) {
		expr->subExpressions[argIndex].replace(arg);
	}

	void BasicBlockWrapper::print (Architecture* arch) {
		printf ("BB %d\n", ssaBB->id);
		printf ("Address 0x%" PRIx64 " - 0x%" PRIx64 "\n", ssaBB->startaddr, ssaBB->endaddr);

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
			if (id == 0xa4)
				i++;
			if (it->regId == reg->id || (replace && it->parentId == reg->parentRef.refId && (reg->offset <= it->offset && (it->offset + it->size) <= (reg->offset + reg->size)))) {
				if (rep) {
					it = list->erase(it);
					continue;
				}
				else {
					*it = { id, reg->id, reg->parentRef.refId, reg->offset, reg->size };
					rep = true;
				}
			}
			++it;
		}
		if (!rep)
			list->push_back({ id, reg->id, reg->parentRef.refId, reg->offset, reg->size });
	}
	void SSAPhiNodeGenerator::addMemDef(HId id, Memory* mem, HList<SSAMemDef>* list, bool replace) {
		bool rep = false;
		int i = 0;
		for (auto it = list->begin(); it != list->end();) {
			if (id == 0xa4)
				i++;
			if (it->memId == mem->id) {
				if (rep) {
					it = list->erase(it);
					continue;
				}
				else {
					*it = { id, mem->id };
					rep = true;
				}
			}
			++it;
		}
		if (!rep)
			list->push_back({ id, mem->id });
	}

	SSAArgument SSAPhiNodeGenerator::getSSAId(BasicBlockWrapper* wrapper, Register* reg) {

		while (true) {
			for (SSARegDef& def : wrapper->outputs) {
				if (def.regId == reg->id) {
					return SSAArgument::createId(def.ssaId);
					break;
				}
			}
			for (SSARegDef& def : wrapper->outputs) {
				if ((def.parentId == (HId)reg->parentRef) && ((def.offset <= reg->offset) && ((reg->offset + reg->size) <= (def.offset + def.size)))) {
					return SSAArgument::createReg(reg, def.ssaId);
				}
			}
			if (wrapper->ssaBB->inBlocks.size() != 1)
				break;
			wrapper = getWrapper(*wrapper->ssaBB->inBlocks.begin());
		}
		assert(wrapper->ssaBB->inBlocks.size() > 1);

		Register* parent_reg = arch->getRegister(reg->parentRef.refId);

		SSAExpression phinode;
		phinode.type = SSAExprType::ePhi;
		phinode.exprtype = SSAType::eUInt;
		phinode.ref = parent_reg;
		phinode.size = parent_reg->size;
		phinode.instrAddr = wrapper->ssaBB->startaddr;
		HId id = function->ssaRep.addAtStart(&phinode, wrapper->ssaBB);
		addRegDef(id, parent_reg, &wrapper->outputs, false);
		for (HId bbId : wrapper->ssaBB->inBlocks) {
			//expressions need to reloaded after each call to getSSAId as they may insert an expression
			function->ssaRep.expressions[id].subExpressions.push_back(SSAArgument::createBlock(bbId));
			function->ssaRep.expressions[id].subExpressions.push_back(getSSAId(getWrapper(bbId), parent_reg));
		}
		return SSAArgument::createReg(parent_reg, id);
	}
	SSAArgument SSAPhiNodeGenerator::getSSAId(BasicBlockWrapper* wrapper, Memory* mem) {

		while (true) {
			for (SSAMemDef& def : wrapper->mem_outputs) {
				if (def.memId == mem->id) {
					return SSAArgument::createMem(mem, def.ssaId);
				}
			}
			if (wrapper->ssaBB->inBlocks.size() != 1)
				break;
			wrapper = getWrapper(*wrapper->ssaBB->inBlocks.begin());
		}
		assert(wrapper->ssaBB->inBlocks.size() > 1);

		SSAExpression phinode;
		phinode.type = SSAExprType::ePhi;
		phinode.exprtype = SSAType::eUInt;
		phinode.ref = mem;
		phinode.size = 0;
		phinode.instrAddr = wrapper->ssaBB->startaddr;
		HId id = function->ssaRep.addAtStart(&phinode, wrapper->ssaBB);
		addMemDef(id, mem, &wrapper->mem_outputs, false);
		for (HId bbId : wrapper->ssaBB->inBlocks) {
			//expressions need to reloaded after each call to getSSAId as they may insert an expression
			function->ssaRep.expressions[id].subExpressions.push_back(SSAArgument::createBlock(bbId));
			function->ssaRep.expressions[id].subExpressions.push_back(getSSAId(getWrapper(bbId), mem));
		}
		return SSAArgument::createMem(mem, id);
	}
	SSAArgument SSAPhiNodeGenerator::getSSAId(BasicBlockWrapper* wrapper, HList<SSARegDef>& defs, Register* reg) {

		for (SSARegDef& def : defs) {
			if (def.regId == reg->id) {
				return SSAArgument::createId(def.ssaId);
			}
		}
		for (SSARegDef& def : defs) {
			if ((def.parentId == (HId)reg->parentRef) && ((def.offset <= reg->offset) && ((reg->offset + reg->size) <= (def.offset + def.size)))) {
				return SSAArgument::createReg(reg, def.ssaId);
			}
		}
		if (wrapper->ssaBB->inBlocks.size() == 1) {
			return getSSAId(getWrapper(*wrapper->ssaBB->inBlocks.begin()), reg);
		}

		assert(wrapper->ssaBB->inBlocks.size() > 1);

		Register* parent_reg = arch->getRegister(reg->parentRef.refId);

		SSAExpression phinode;
		phinode.type = SSAExprType::ePhi;
		phinode.exprtype = SSAType::eUInt;
		phinode.ref = parent_reg;
		phinode.size = parent_reg->size;
		phinode.instrAddr = wrapper->ssaBB->startaddr;
		HId id = function->ssaRep.addAtStart(&phinode, wrapper->ssaBB);
		addRegDef(id, parent_reg, &defs, false);
		bool contains = false;
		for (SSARegDef& def : wrapper->outputs) {
			if (def.regId == parent_reg->id || ((def.parentId == (HId)parent_reg->parentRef) && ((def.offset <= parent_reg->offset) && ((parent_reg->offset + parent_reg->size) <= (def.offset + def.size))))) {
				contains = true;
				break;
			}
		}
		if (!contains) {
			addRegDef(id, parent_reg, &wrapper->outputs, false);
		}
		for (HId bbId : wrapper->ssaBB->inBlocks) {
			//expressions need to reloaded after each call to getSSAId as they may insert an expression
			function->ssaRep.expressions[id].subExpressions.push_back(SSAArgument::createBlock(bbId));

			//do not inline because for some inexplicaple reason sometimes the push_back does not work inlined
			SSAArgument a = getSSAId(getWrapper(bbId), parent_reg);
			function->ssaRep.expressions[id].subExpressions.push_back(a);
		}
		return SSAArgument::createReg(parent_reg, id);
	}
	SSAArgument SSAPhiNodeGenerator::getSSAId(BasicBlockWrapper* wrapper, HList<SSAMemDef>& defs, Memory* mem) {

		for (SSAMemDef& def : defs) {
			if (def.memId == mem->id) {
				return SSAArgument::createMem(mem, def.ssaId);
			}
		}
		if (wrapper->ssaBB->inBlocks.size() == 1) {
			return getSSAId(getWrapper(*wrapper->ssaBB->inBlocks.begin()), mem);
		}

		assert(wrapper->ssaBB->inBlocks.size() > 1);

		SSAExpression phinode;
		phinode.type = SSAExprType::ePhi;
		phinode.exprtype = SSAType::eUInt;
		phinode.ref = mem;
		phinode.size = 0;
		phinode.instrAddr = wrapper->ssaBB->startaddr;
		HId id = function->ssaRep.addAtStart(&phinode, wrapper->ssaBB);
		addMemDef(id, mem, &defs, false);
		bool contains = false;
		for (SSAMemDef& def : wrapper->mem_outputs) {
			if (def.memId == mem->id) {
				contains = true;
				break;
			}
		}
		if (!contains) {
			addMemDef(id, mem, &wrapper->mem_outputs, false);
		}
		for (HId bbId : wrapper->ssaBB->inBlocks) {
			//expressions need to reloaded after each call to getSSAId as they may insert an expression
			function->ssaRep.expressions[id].subExpressions.push_back(SSAArgument::createBlock(bbId));
			function->ssaRep.expressions[id].subExpressions.push_back(getSSAId(getWrapper(bbId), mem));
		}
		return SSAArgument::createMem(mem, id);
	}

	bool SSAPhiNodeGenerator::doTransformation (Binary* binary, Function* function) {

		printf ("Generating Phi-Nodes for Function at Address 0x%" PRIx64 "\n", function->baseaddr);
		this->binary = binary;
		this->function = function;

		bbwrappers.clear();
		bbwrappers.resize(function->ssaRep.bbs.size());
		for (size_t i = 0; i < function->ssaRep.bbs.list.size(); i++) {
			for (auto it = function->ssaRep.bbs.list[i].exprIds.begin(); it != function->ssaRep.bbs.list[i].exprIds.end(); ) {
				HId id = *it;
				SSAExpression& expr = function->ssaRep.expressions[id];
				if (expr.type == SSAExprType::ePhi) {
					it = function->ssaRep.removeExpr(function->ssaRep.bbs.list[i].exprIds, it);
					continue;
				}
				for (SSAArgument& arg : expr.subExpressions) {
					if (arg.ref.isLocation(SSALocation::eReg) || arg.ref.isLocation(SSALocation::eMem)) {
						arg.ssaId = 0;
					}
				}
				++it;
			}
			bbwrappers[i].ssaBB = &function->ssaRep.bbs.list[i];
		}
		for (BasicBlockWrapper& bbwrapper : bbwrappers) {//iterate Blocks
			for (size_t j = 0; j < bbwrapper.ssaBB->exprIds.size(); j++) {//iterate Expressions
				HId id = bbwrapper.ssaBB->exprIds[j];
				SSAExpression* expr = function->ssaRep.expressions.get(id);
				switch (expr->ref.location) {
				case SSALocation::eReg:
					addRegDef(expr->id, arch->getRegister(expr->ref.id), &bbwrapper.outputs, !EXPR_IS_TRANSPARENT(expr->type));
					break;
				case SSALocation::eMem:
					addMemDef(expr->id, arch->getMemory(expr->ref.id), &bbwrapper.mem_outputs, !EXPR_IS_TRANSPARENT(expr->type));
					break;
				default:
					break;
				}
			}
		}

		for (BasicBlockWrapper& bbwrapper : bbwrappers) {//iterate Blocks
			HList<SSARegDef> defs;
			HList<SSAMemDef> mem_defs;
			assert(bbwrapper.ssaBB->id == 1 || bbwrapper.ssaBB->inBlocks.size() != 0);
			for (size_t j = 0; j < bbwrapper.ssaBB->exprIds.size(); j++) {//iterate Expressions
				HId id = bbwrapper.ssaBB->exprIds[j];
				SSAExpression* expr = function->ssaRep.expressions.get(id);
				for (size_t i = 0; i < expr->subExpressions.size(); i++) {
					if (expr->subExpressions[i].type == SSAArgType::eId && !expr->subExpressions[i].ssaId) {
						if (expr->subExpressions[i].ref.isLocation(SSALocation::eReg)) {
							Register* reg = arch->getRegister(expr->subExpressions[i].ref.id);
							assert(reg && reg->id);
							SSAArgument anArg = getSSAId(&bbwrapper, defs, reg);
							assert(anArg.ssaId);
							expr = function->ssaRep.expressions.get(id);//reload Expression
							expr->subExpressions[i].replace(anArg);
						}
						else if (expr->subExpressions[i].ref.isLocation(SSALocation::eMem)) {
							Memory* mem = arch->getMemory(expr->subExpressions[i].ref.id);
							assert(mem && mem->id);
							SSAArgument anArg = getSSAId(&bbwrapper, mem_defs, mem);
							assert(anArg.ssaId);
							expr = function->ssaRep.expressions.get(id);//reload Expression
							expr->subExpressions[i].replace(anArg);
						}
						else
							assert(false);
					}
				}
				switch (expr->ref.location) {
				case SSALocation::eReg:
					addRegDef(expr->id, arch->getRegister(expr->ref.id), &defs, !EXPR_IS_TRANSPARENT(expr->type));
					break;
				case SSALocation::eMem:
					addMemDef(expr->id, arch->getMemory(expr->ref.id), &mem_defs, !EXPR_IS_TRANSPARENT(expr->type));
					break;
				default:
					break;
				}
			}
		}
		function->ssaRep.compress();
		return true;
	}

}
