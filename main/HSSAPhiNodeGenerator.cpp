#include "HSSAPhiNodeGenerator.h"
#include "HFunction.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {


	void BasicBlockWrapper::print (HArchitecture* arch) {
		printf ("BB %d\n", ssaBB->id);
		printf ("Address 0x%x - 0x%x\n", ssaBB->startaddr, ssaBB->endaddr);
		printf ("Fallthrough %d\n", ssaBB->fallthroughId);

		printf ("InBlocks ");
		for (HId& id : inBlocks) {
			printf ("%d, ", id);
		}
		printf ("\n");
		printf ("OutBlocks ");
		for (HId& id : outBlocks) {
			printf ("%d, ", id);
		}
		printf ("\n");


		printf ("Inputs ");
		for (HSSARegDef& def : inputs) {
			printf ("%s, ", arch->getRegister (def.regId)->name.cstr());
		}
		printf ("\n");
		printf ("Outputs ");
		for (HSSARegDef& def : outputs) {
			printf ("%s, ", arch->getRegister (def.regId)->name.cstr());
		}
		printf ("\n");
		printf ("InputMems ");
		for (HSSAMemDef& def : inputMems) {
			printf ("%s, ", arch->getMemory(def.memId)->name.cstr());
		}
		printf ("\n");
		printf ("OutputMems ");
		for (HSSAMemDef& def : outputMems) {
			printf ("%s, ", arch->getMemory (def.memId)->name.cstr());
		}
		printf ("\n");
	}


	void addRegDef (HId id, HRegister* reg, HList<HSSARegDef>* list, bool replace) {
		bool rep = false;
		for (auto it = list->begin(); it != list->end();) {
			HSSARegDef& def = *it;
			if (def.regId == reg->id || (replace && def.parentId == reg->parentId && (reg->offset <= def.offset && (def.offset + def.size) <= (reg->offset + reg->size)))) {
				if (rep) {
					list->erase (it);
					continue;
				} else {
					def = {id, reg->id, reg->parentId, reg->offset, reg->size};
					rep = true;
				}
			}
			++it;
		}
		if (!rep)
			list->push_back ({id, reg->id, reg->parentId, reg->offset, reg->size});
	}
	void addMemDef (HId id, HMemory* mem, HList<HSSAMemDef>* list) {
		bool rep = false;
		for (auto it = list->begin(); it != list->end();) {
			HSSAMemDef& def = *it;
			if (def.memId == mem->id) {
				if (rep) {
					list->erase (it);
					continue;
				} else {
					def = {id, mem->id};
					rep = true;
				}
			}
			++it;
		}
		if (!rep)
			list->push_back ({id, mem->id});
	}
	
	void HSSAPhiNodeGenerator::resolveRegs () {

		bbwrappers.clear();
		for (HSSABB& bb : function->ssaRep.bbs) {
			BasicBlockWrapper bbwrapper;
			bbwrapper.ssaBB = &bb;
			bbwrappers.push_back (bbwrapper);
		}

		for (BasicBlockWrapper& bbwrapper : bbwrappers) {

			for (HSSABB& bb2 : function->ssaRep.bbs) {
				if (bbwrapper.ssaBB->id == bb2.fallthroughId) {
					bbwrapper.inBlocks.push_back (bb2.id);
				}
				if (bb2.exprIds.size()) {
					HSSAExpression* lastExpr = function->ssaRep.expressions.get (bb2.exprIds.back());
					if (lastExpr->type == HSSA_EXPR_JMP && lastExpr->subExpressions[0].type == HSSA_ARGTYPE_BLOCK) {
						if (bbwrapper.ssaBB->id == lastExpr->subExpressions[0].uval) {
							bbwrapper.inBlocks.push_back (bb2.id);
						}
					} else if (lastExpr->type == HSSA_EXPR_CJMP && lastExpr->subExpressions[1].type == HSSA_ARGTYPE_BLOCK) {
						if (bbwrapper.ssaBB->id == lastExpr->subExpressions[1].uval) {
							bbwrapper.inBlocks.push_back (bb2.id);
						}
					}
				}
			}
			if (bbwrapper.ssaBB->fallthroughId)
				bbwrapper.outBlocks.push_back (bbwrapper.ssaBB->fallthroughId);
			if (bbwrapper.ssaBB->exprIds.size()) {
				HSSAExpression* lastExpr = function->ssaRep.expressions.get (bbwrapper.ssaBB->exprIds.back());
				if (lastExpr->type == HSSA_EXPR_JMP && lastExpr->subExpressions[0].type == HSSA_ARGTYPE_BLOCK) {
					bbwrapper.outBlocks.push_back (lastExpr->subExpressions[0].uval);
				} else if (lastExpr->type == HSSA_EXPR_CJMP && lastExpr->subExpressions[1].type == HSSA_ARGTYPE_BLOCK) {
					bbwrapper.outBlocks.push_back (lastExpr->subExpressions[1].uval);
				}
			}
			for (auto it = bbwrapper.ssaBB->exprIds.begin(); it != bbwrapper.ssaBB->exprIds.end(); ++it) {
				HId id = *it;
				HSSAExpression* expr = function->ssaRep.expressions.get (id);
				for (int i = 0; i < expr->subExpressions.size(); i++) {
					if(expr->subExpressions[i].id == 0){
						if (expr->subExpressions[i].type == H_ARGTYPE_REG) {
							HRegister* reg = arch->getRegister (expr->subExpressions[i].reg);
							bool found = false;
							for (HSSARegDef& def : bbwrapper.outputs) {
								if (def.regId == reg->id) {
									expr->subExpressions[i].id = def.ssaId;
									found = true;
									break;
								}
							}
							if (!found) {
								for (HSSARegDef& def : bbwrapper.outputs) {
									if ( (def.parentId == reg->parentId) && ( (def.offset <= reg->offset) && ( (reg->offset + reg->size) <= (def.offset + def.size)))) {
										
										HSSAExpression newExpr;
										newExpr.type = HSSA_EXPR_SPLIT;
										newExpr.exprtype = HSSA_TYPE_UINT;
										newExpr.instrAddr = expr->instrAddr;
										newExpr.regId = reg->id;
										newExpr.subExpressions.push_back (HArgument::createReg (reg, def.ssaId));
										newExpr.subExpressions.push_back (HArgument::createVal (reg->offset - def.offset, arch->bitbase));
										newExpr.subExpressions.push_back (HArgument::createVal ( (def.offset + def.size) - (reg->offset + reg->size), arch->bitbase));

										HId newId = function->ssaRep.expressions.push_back (newExpr);
										it = bbwrapper.ssaBB->exprIds.insert (it, newId);

										expr = function->ssaRep.expressions.get (id); //reload expression in case we have a reallocate
										expr->subExpressions[i].id = newId;

										found = true;
										break;
									}
								}
							}
							if (!found)
								addRegDef (0, reg, &bbwrapper.inputs, false);
						}else if(expr->subExpressions[i].type == H_ARGTYPE_MEM){
							HMemory* mem = arch->getMemory (expr->subExpressions[i].index);
							bool found = false;
							for (HSSAMemDef& def : bbwrapper.outputMems) {
								if (def.memId == mem->id) {
									expr->subExpressions[i].id = def.ssaId;
									found = true;
									break;
								}
							}
							if(!found)
								addMemDef (0, mem, &bbwrapper.inputMems);
						}
					}
				}
				if (expr->regId) {
					HRegister* reg = arch->getRegister (expr->regId);
					addRegDef (expr->id, reg, &bbwrapper.outputs, ! (expr->type == HSSA_EXPR_UPDATEPART || expr->type == HSSA_EXPR_PHI));
				}
				if (expr->memId) {
					HMemory* mem = arch->getMemory (expr->memId);
					addMemDef (expr->id, mem, &bbwrapper.outputMems);
				}
			}
		}

	}

	void HSSAPhiNodeGenerator::doTransformation (HFunction* function) {

		printf ("Generating Phi-Nodes for Function at Address 0x%x\n", function->baseaddr);
		this->function = function;

		for (HSSABB& bb : function->ssaRep.bbs) {
			for (HId id : bb.exprIds) {
				HSSAExpression* expr = function->ssaRep.expressions.get (id);
				if (expr->type == HSSA_EXPR_PHI) //don't clear already created phi nodes
					continue;
				for (int i = 0; i < expr->subExpressions.size(); i++) {
					HArgument& arg = expr->subExpressions[i];
					if (arg.type == H_ARGTYPE_REG || arg.type == H_ARGTYPE_MEM || arg.type == H_ARGTYPE_STACK) //reset id of register/memory/stack so that we can redo them to find non defined reg-arguments
						arg.id = 0;
				}
			}
		}

		resolveRegs();

		for (BasicBlockWrapper& wrap : bbwrappers) {

			for (HSSARegDef& regDef : wrap.inputs) {
				HId gatheredIds[bbwrappers.size()] = {0};
				uint64_t gatheredIdCount = 0;
				HId visitedBlocks[bbwrappers.size()] = {wrap.ssaBB->id};
				uint64_t visitedBlockCount = 1;

				HRegister* reg = arch->getRegister (regDef.regId);

				//printf("Searching Defs for Reg %s in Block %d\n", reg->name.cstr(), wrap.ssaBB->id);
				for (HId& inBlockId : wrap.inBlocks) {
					handleBBs (getWrapper (inBlockId), reg, gatheredIds, &gatheredIdCount, visitedBlocks, &visitedBlockCount);
				}
				//printf("Reg: %s Count %d\n", reg->name.cstr(), gatheredIdCount);
				assert (gatheredIdCount);

				HSSAExpression phinode;
				phinode.type = HSSA_EXPR_PHI;
				phinode.exprtype = HSSA_TYPE_UINT;
				phinode.regId = reg->id;
				phinode.size = reg->size;
				phinode.instrAddr = wrap.ssaBB->startaddr;
				for (int i = 0; i < gatheredIdCount; i++) {
					phinode.subExpressions.push_back (HArgument::createReg (reg, gatheredIds[i]));
				}
				HId exprId = function->ssaRep.expressions.push_back (phinode);
				wrap.ssaBB->exprIds.insert (wrap.ssaBB->exprIds.begin(), exprId);
				bool needInOutput = true;
				for (HSSARegDef& def : wrap.outputs) {
					if (def.parentId == reg->parentId) {
						needInOutput = false;
						break;
					}
				}
				if (needInOutput) {
					addRegDef (exprId, reg, &wrap.outputs, true);
				}
			}
			
			for (HSSAMemDef& memDef : wrap.inputMems) {
				HId gatheredIds[bbwrappers.size()] = {0};
				uint64_t gatheredIdCount = 0;
				HId visitedBlocks[bbwrappers.size()] = {wrap.ssaBB->id};
				uint64_t visitedBlockCount = 1;
				
				HMemory* mem = arch->getMemory (memDef.memId);
				
				for (HId& inBlockId : wrap.inBlocks) {
					handleBBs (getWrapper (inBlockId), mem, gatheredIds, &gatheredIdCount, visitedBlocks, &visitedBlockCount);
				}
				assert (gatheredIdCount);
				
				HSSAExpression phinode;
				phinode.type = HSSA_EXPR_PHI;
				phinode.exprtype = HSSA_TYPE_MEM;
				phinode.memId = mem->id;
				phinode.size = 0;
				phinode.instrAddr = wrap.ssaBB->startaddr;
				for (int i = 0; i < gatheredIdCount; i++) {
					phinode.subExpressions.push_back (HArgument::createMem (mem, gatheredIds[i]));
				}
				HId exprId = function->ssaRep.expressions.push_back (phinode);
				wrap.ssaBB->exprIds.insert (wrap.ssaBB->exprIds.begin(), exprId);
				bool needInOutput = true;
				for (HSSAMemDef& def : wrap.outputMems) {
					if (def.memId == mem->id) {
						needInOutput = false;
						break;
					}
				}
				if (needInOutput) {
					addMemDef (exprId, mem, &wrap.outputMems);
				}
			}
			//wrap.print(arch);
		}

		resolveRegs();
	}

	void HSSAPhiNodeGenerator::handleBBs (BasicBlockWrapper* wrapper, HRegister* reg,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount) {
		//printf("\nHandling Block %d\n", wrapper->ssaBB->id);

		//printf("Found no match on BB %d\n", wrapper->ssaBB->id);

		HSSARegDef* foundParentDef = nullptr;
		for (HSSARegDef& regDef : wrapper->outputs) {
			if (regDef.parentId == reg->parentId) {
				if (regDef.regId == reg->id) {
					gatheredIds[ (*gatheredIdCount)++] = regDef.ssaId;
					//printf("\Found perfect Match %d\n", regDef.ssaId);
					return;
				} else if (regDef.regId == reg->parentId) {
					//printf("\Found parent Match %d\n", regDef.ssaId);
					foundParentDef = &regDef;
				}
			}
		}
		if (foundParentDef) {
			//printf("Found parent Match %d\n", foundParentDef->ssaId);
			HSSAExpression expr;
			expr.type = HSSA_EXPR_SPLIT;
			expr.exprtype = HSSA_TYPE_UINT;
			expr.size = reg->size;
			expr.regId = reg->id;
			expr.subExpressions.push_back (HArgument::createReg (arch->getRegister (foundParentDef->regId), foundParentDef->ssaId));
			expr.subExpressions.push_back (HArgument::createVal (reg->offset, arch->bitbase));
			expr.subExpressions.push_back (HArgument::createVal (reg->size, arch->bitbase));
			bool found = false;
			for(auto it = wrapper->ssaBB->exprIds.begin(); it != wrapper->ssaBB->exprIds.end(); ++it){
				if(foundParentDef->ssaId == *it){
					expr.instrAddr = function->ssaRep.expressions[foundParentDef->ssaId].instrAddr;
					HId exprId = function->ssaRep.expressions.push_back (expr);
					wrapper->ssaBB->exprIds.insert(++it, exprId);
					addRegDef (exprId, reg, &wrapper->outputs, false);
					gatheredIds[ (*gatheredIdCount)++] = exprId;
					found = true;
					break;
				}
			}
			assert(found);
		} else {
			for (int i = 0; i < *visitedBlockCount; i++) {
				if (visitedBlocks[i] == wrapper->ssaBB->id) {
					//printf("Already Visited BB %d\n", wrapper->ssaBB->id);
					return;
				}
			}
			visitedBlocks[ (*visitedBlockCount)++] = wrapper->ssaBB->id;
			
			for (HId& inBlockId : wrapper->inBlocks) {
				handleBBs (getWrapper (inBlockId), reg, gatheredIds, gatheredIdCount, visitedBlocks, visitedBlockCount);
			}
		}
	}
	void HSSAPhiNodeGenerator::handleBBs (BasicBlockWrapper* wrapper, HMemory* mem,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount) {
		//printf("\nHandling Block %d\n", wrapper->ssaBB->id);

		//printf("Found no match on BB %d\n", wrapper->ssaBB->id);

		HSSAMemDef* foundDef = nullptr;
		for (HSSAMemDef& memDef : wrapper->outputMems) {
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
		
		for (HId& inBlockId : wrapper->inBlocks) {
			handleBBs (getWrapper (inBlockId), mem, gatheredIds, gatheredIdCount, visitedBlocks, visitedBlockCount);
		}
	}

}
