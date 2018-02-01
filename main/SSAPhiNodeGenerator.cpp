#include "SSAPhiNodeGenerator.h"
#include "Function.h"
#include "Architecture.h"
#include <assert.h>

namespace holodec {


	void setSSAID (SSARepresentation* ssaRep, SSAExpression* expr, HId argIndex, HId id) {
		SSAArgument arg = expr->subExpressions[argIndex];
		arg.type = SSAArgType::eId;
		arg.ssaId = id;
		expr->subExpressions[argIndex] = arg;
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


		printf ("Inputs ");
		for (SSARegDef& def : inputs) {
			printf ("%s, ", arch->getRegister (def.regId)->name.cstr());
		}
		printf ("\n");
		printf ("Outputs ");
		for (SSARegDef& def : outputs) {
			printf ("%s, ", arch->getRegister (def.regId)->name.cstr());
		}
		printf ("\n");
		printf ("InputMems ");
		for (SSAMemDef& def : inputMems) {
			printf ("%s, ", arch->getMemory (def.memId)->name.cstr());
		}
		printf ("\n");
		printf ("OutputMems ");
		for (SSAMemDef& def : outputMems) {
			printf ("%s, ", arch->getMemory (def.memId)->name.cstr());
		}
		printf ("\n");
	}


	void addRegDef(HId id, Register* reg, HList<SSARegDef>* list, bool replace) {
		bool rep = false;
		int i = 0;
		for (auto it = list->begin(); it != list->end();) {
			if(id == 0xa4)
				i++;
			SSARegDef& def = *it;
			if (def.regId == reg->id || (replace && def.parentId == reg->parentRef.refId && (reg->offset <= def.offset && (def.offset + def.size) <= (reg->offset + reg->size)))) {
				if (rep) {
					it = list->erase (it);
					continue;
				} else {
					def = {id, reg->id, reg->parentRef.refId, reg->offset, reg->size};
					rep = true;
				}
			}
			++it;
		}
		if (!rep)
			list->push_back ({id, reg->id, reg->parentRef.refId, reg->offset, reg->size});
	}
	void addMemDef (HId id, Memory* mem, HList<SSAMemDef>* list) {
		bool rep = false;
		for (auto it = list->begin(); it != list->end();) {
			SSAMemDef& def = *it;
			if (def.memId == mem->id) {
				if (rep) {
					it = list->erase (it);
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

	void SSAPhiNodeGenerator::resolveRegs () {

		bbwrappers.clear();
		for (SSABB& bb : function->ssaRep.bbs) {
			BasicBlockWrapper bbwrapper;
			bbwrapper.ssaBB = &bb;
			bbwrappers.push_back (bbwrapper);
		}

		for (BasicBlockWrapper& bbwrapper : bbwrappers) {

			for (auto it = bbwrapper.ssaBB->exprIds.begin(); it != bbwrapper.ssaBB->exprIds.end(); ++it) {
				HId id = *it;
				SSAExpression* expr = function->ssaRep.expressions.get (id);
				for (size_t i = 0; i < expr->subExpressions.size(); i++) {
					if (expr->subExpressions[i].type == SSAArgType::eId && !expr->subExpressions[i].ssaId) {
						if (expr->subExpressions[i].location == SSAExprLocation::eReg) {
							Register* reg = arch->getRegister (expr->subExpressions[i].locref.refId);
							assert (reg->id);
							bool found = false;
							for (SSARegDef& def : bbwrapper.outputs) {
								if (def.regId == reg->id) {
									setSSAID (&function->ssaRep, expr, i, def.ssaId);
									found = true;
									break;
								}
							}
							if (!found) {
								for (SSARegDef& def : bbwrapper.outputs) {
									if ( (def.parentId == (HId) reg->parentRef) && ( (def.offset <= reg->offset) && ( (reg->offset + reg->size) <= (def.offset + def.size)))) {

										SSAExpression newExpr;
										newExpr.type = SSAExprType::eSplit;
										newExpr.size = static_cast<uint32_t>((def.offset + def.size) - (reg->offset + reg->size));
										newExpr.exprtype = SSAType::eUInt;
										newExpr.instrAddr = expr->instrAddr;
										newExpr.location = SSAExprLocation::eReg;
										newExpr.locref = {reg->id, 0};
										newExpr.subExpressions = {
											SSAArgument::createReg (reg, def.ssaId),
											SSAArgument::createUVal (reg->offset - def.offset, arch->bitbase),
											SSAArgument::createUVal (newExpr.size, arch->bitbase)
										};

										it = function->ssaRep.addBefore (&newExpr, bbwrapper.ssaBB->exprIds, it);

										expr = function->ssaRep.expressions.get (id); //reload expression in case we have a reallocate
										setSSAID (&function->ssaRep, expr, static_cast<HId>(i), *it);

										found = true;
										break;
									}
								}
							}
							if (!found) {
								addRegDef (0, reg, &bbwrapper.inputs, false);
							}
						} else if (expr->subExpressions[i].location == SSAExprLocation::eMem) {
							Memory* mem = arch->getMemory (expr->subExpressions[i].locref.refId);
							bool found = false;
							for (SSAMemDef& def : bbwrapper.outputMems) {
								if (def.memId == mem->id) {
									setSSAID (&function->ssaRep, expr, static_cast<HId>(i), def.ssaId);
									found = true;
									break;
								}
							}
							if (!found)
								addMemDef (0, mem, &bbwrapper.inputMems);
						}
					}
				}
				switch (expr->location) {
				case SSAExprLocation::eReg:
					addRegDef (expr->id, arch->getRegister (expr->locref.refId), &bbwrapper.outputs, ! EXPR_IS_TRANSIENT (expr->type));
					break;
				case SSAExprLocation::eMem:
					addMemDef (expr->id, arch->getMemory (expr->locref.refId), &bbwrapper.outputMems);
					break;
				default:
					break;
				}
			}
		}

	}

	void SSAPhiNodeGenerator::doTransformation (Binary* binary, Function* function) {


		printf ("Generating Phi-Nodes for Function at Address 0x%" PRIx64 "\n", function->baseaddr);
		this->binary = binary;
		this->function = function;
		
		for (SSABB& bb : function->ssaRep.bbs) {
			for (HId id : bb.exprIds) {
				SSAExpression* expr = function->ssaRep.expressions.get (id);
				if (expr->type == SSAExprType::ePhi) //don't clear already created phi nodes
					continue;
				for (size_t i = 0; i < expr->subExpressions.size(); i++) {
					SSAArgument& arg = expr->subExpressions[i];
					//reset id of register/memory/stack so that we can redo them to find non defined reg-arguments
					if (arg.location != SSAExprLocation::eNone) {
						setSSAID (&function->ssaRep, expr, static_cast<HId>(i), 0);
					}
				}
			}
		}

		resolveRegs();

		for (BasicBlockWrapper& wrap : bbwrappers) {
			for (SSARegDef& regDef : wrap.inputs) {

#if defined(__GNUC__) || defined(__MINGW32__)
				HId gatheredIds[bbwrappers.size()] = {0};
				HId visitedBlocks[bbwrappers.size()] = {wrap.ssaBB->id};
#else
				HId* gatheredIds = new HId[bbwrappers.size()];
				memset(gatheredIds, 0, sizeof(HId));
				HId* visitedBlocks = new HId[bbwrappers.size()];
				memset(visitedBlocks, 0, sizeof(HId));
				visitedBlocks[0] = wrap.ssaBB->id;
#endif
				uint64_t gatheredIdCount = 0;
				uint64_t visitedBlockCount = 1;

				Register* reg = arch->getRegister (regDef.regId);

				if (!reg->id)
					printf ("%d - %d %s\n", wrap.ssaBB->id, regDef.regId, reg->name.cstr());

				//printf ("Searching Defs for Reg %s in Block %d\n", reg->name.cstr(), wrap.ssaBB->id);
				for (HId inBlockId : wrap.ssaBB->inBlocks) {
					handleBBs (getWrapper (inBlockId), reg, gatheredIds, &gatheredIdCount, visitedBlocks, &visitedBlockCount);
				}
				//printf ("Reg: %s Count %d\n", reg->name.cstr(), gatheredIdCount);
				assert (gatheredIdCount);

				SSAExpression phinode;
				phinode.type = SSAExprType::ePhi;
				phinode.exprtype = SSAType::eUInt;
				phinode.location = SSAExprLocation::eReg;
				phinode.locref = {reg->id, 0};
				phinode.size = reg->size;
				phinode.instrAddr = wrap.ssaBB->startaddr;
				phinode.subExpressions.resize (gatheredIdCount);
				for (uint64_t i = 0; i < gatheredIdCount; i++) {
					phinode.subExpressions[i] = SSAArgument::createReg (reg, gatheredIds[i]);
				}
				HId exprId = function->ssaRep.addAtStart (&phinode, wrap.ssaBB);
				bool needInOutput = true;
				for (SSARegDef& def : wrap.outputs) {
					if (def.parentId == reg->parentRef.refId) {
						needInOutput = false;
						break;
					}
				}
				if (needInOutput) {
					addRegDef (exprId, reg, &wrap.outputs, true);
				}
#if !defined(__GNUC__) || !defined(__MINGW32__)
				delete gatheredIds;
				delete visitedBlocks;
#endif
			}
			/*
			for (SSAMemDef& memDef : wrap.inputMems) {
				HId gatheredIds[bbwrappers.size()] = {0};
				uint64_t gatheredIdCount = 0;
				HId visitedBlocks[bbwrappers.size()] = {wrap.ssaBB->id};
				uint64_t visitedBlockCount = 1;

				Memory* mem = arch->getMemory (memDef.memId);

				for (HId inBlockId : wrap.ssaBB->inBlocks) {
					handleBBs (getWrapper (inBlockId), mem, gatheredIds, &gatheredIdCount, visitedBlocks, &visitedBlockCount);
				}
				assert (gatheredIdCount);

				SSAExpression phinode;
				phinode.type = SSA_EXPR_PHI;
				phinode.exprtype = SSA_TYPE_MEMACCESS;
				phinode.location = SSA_LOCATION_MEM;
				phinode.locref = {mem->id, 0};
				phinode.size = 0;
				phinode.instrAddr = wrap.ssaBB->startaddr;
				for (int i = 0; i < gatheredIdCount; i++) {
					phinode.subExpressions.push_back (SSAArgument::createMem (mem->id, gatheredIds[i]));
				}
				HId exprId = function->ssaRep.addAtStart(&phinode, wrap.ssaBB);
				bool needInOutput = true;
				for (SSAMemDef& def : wrap.outputMems) {
					if (def.memId == mem->id) {
						needInOutput = false;
						break;
					}
				}
				if (needInOutput) {
					addMemDef (exprId, mem, &wrap.outputMems);
				}
			}*/
			//wrap.print(arch);
		}

		resolveRegs();
		function->ssaRep.compress();
	}

	void SSAPhiNodeGenerator::handleBBs (BasicBlockWrapper* wrapper, Register* reg,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount) {
		//printf ("\nHandling Block %d\n", wrapper->ssaBB->id);

		//printf ("Found no match on BB %d\n", wrapper->ssaBB->id);

		SSARegDef* foundParentDef = nullptr;
		for (SSARegDef& regDef : wrapper->outputs) {
			if (regDef.parentId == reg->parentRef.refId) {
				if (regDef.regId == reg->id) {
					gatheredIds[ (*gatheredIdCount)++] = regDef.ssaId;
					//printf ("\Found perfect Match %d\n", regDef.ssaId);
					return;
				} else if (regDef.regId == reg->parentRef.refId) {
					//printf ("\Found parent Match %d\n", regDef.ssaId);
					foundParentDef = &regDef;
				}
			}
		}
		if (foundParentDef) {
			//printf("Found parent Match %d\n", foundParentDef->ssaId);
			SSAExpression expr;
			expr.type = SSAExprType::eSplit;
			expr.exprtype = SSAType::eUInt;
			expr.size = reg->size;
			expr.location = SSAExprLocation::eReg;
			expr.locref = {reg->id, 0};
			expr.subExpressions = {
				SSAArgument::createReg (arch->getRegister (foundParentDef->regId), foundParentDef->ssaId),
				SSAArgument::createUVal (reg->offset, arch->bitbase),
				SSAArgument::createUVal (reg->size, arch->bitbase)
			};
			bool found = false;
			for (auto it = wrapper->ssaBB->exprIds.begin(); it != wrapper->ssaBB->exprIds.end(); ++it) {
				if (foundParentDef->ssaId == *it) {
					expr.instrAddr = function->ssaRep.expressions[foundParentDef->ssaId].instrAddr;

					HId exprId = *function->ssaRep.addAfter (&expr, wrapper->ssaBB->exprIds, it);
					addRegDef (exprId, reg, &wrapper->outputs, false);
					gatheredIds[ (*gatheredIdCount)++] = exprId;
					found = true;
					break;
				}
			}
			assert (found);
		} else {
			for (uint64_t i = 0; i < *visitedBlockCount; i++) {
				if (visitedBlocks[i] == wrapper->ssaBB->id) {
					//printf("Already Visited BB %d\n", wrapper->ssaBB->id);
					return;
				}
			}
			visitedBlocks[ (*visitedBlockCount)++] = wrapper->ssaBB->id;

			for (HId inBlockId : wrapper->ssaBB->inBlocks) {
				handleBBs (getWrapper (inBlockId), reg, gatheredIds, gatheredIdCount, visitedBlocks, visitedBlockCount);
			}
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
