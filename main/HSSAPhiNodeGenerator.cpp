#include "HSSAPhiNodeGenerator.h"
#include "HFunction.h"
#include "HArchitecture.h"
#include <assert.h>

namespace holodec {

	
	void BasicBlockWrapper::print(HArchitecture* arch) {
		printf("BB %d\n", ssaBB->id);
		printf("Address 0x%x - 0x%x\n", ssaBB->startaddr, ssaBB->endaddr);
		printf("Fallthrough %d\n", ssaBB->fallthroughId);
		
		printf("InBlocks ");
		for(HId& id : inBlocks){
			printf("%d, ", id);
		}
		printf("\n");
		printf("OutBlocks ");
		for(HId& id : outBlocks){
			printf("%d, ", id);
		}
		printf("\n");
		
		
		printf("Inputs ");
		for(HSSARegDef& def : inputs){
			printf("%s, ", arch->getRegister(def.regId)->name.cstr());
		}
		printf("\n");
		printf("Outputs ");
		for(HSSARegDef& def : outputs){
			printf("%s, ", arch->getRegister(def.regId)->name.cstr());
		}
		printf("\n");
	}
	
	
	void addRegDef(HId id, HRegister* reg, HList<HSSARegDef>* list, bool replace){
		bool rep = false;
		for(auto it = list->begin(); it != list->end();){
			HSSARegDef& def = *it;
			if(def.regId == reg->id || (replace && def.parentId == reg->parentId && (reg->offset <= def.offset && (def.offset + def.size) <= (reg->offset + reg->size)))){
				if(rep){
					list->erase(it);
					continue;
				}else{
					def.ssaId = id;
					rep = true;
				}
			}
			++it;
		}
		if(!rep)
			list->push_back({id,reg->id, reg->parentId, reg->size, reg->offset});
	}
	void HSSAPhiNodeGenerator::resolveRegs (){
		
		bbwrappers.clear();
		for(HSSABB& bb : function->ssaRep.bbs){
			BasicBlockWrapper bbwrapper;
			bbwrapper.ssaBB = &bb;
			bbwrappers.push_back(bbwrapper);
		}
		
		for(BasicBlockWrapper& bbwrapper : bbwrappers){
			
			for(HSSABB& bb2 : function->ssaRep.bbs){
				if(bbwrapper.ssaBB->id == bb2.fallthroughId){
					bbwrapper.inBlocks.push_back(bb2.id);
				}
				if(bb2.exprIds.size()){
					HSSAExpression* lastExpr = function->ssaRep.expressions.get(bb2.exprIds.back());
					if(lastExpr->type == HSSA_EXPR_JMP && lastExpr->subExpressions[0].type == HSSA_ARGTYPE_BLOCK){
						if(bbwrapper.ssaBB->id == lastExpr->subExpressions[0].uval){
							bbwrapper.inBlocks.push_back(bb2.id);
						}
					}else if(lastExpr->type == HSSA_EXPR_CJMP && lastExpr->subExpressions[1].type == HSSA_ARGTYPE_BLOCK){
						if(bbwrapper.ssaBB->id == lastExpr->subExpressions[1].uval){
							bbwrapper.inBlocks.push_back(bb2.id);
						}
					}
				}
			}
			if(bbwrapper.ssaBB->fallthroughId)
				bbwrapper.outBlocks.push_back(bbwrapper.ssaBB->fallthroughId);
			if(bbwrapper.ssaBB->exprIds.size()){
				HSSAExpression* lastExpr = function->ssaRep.expressions.get(bbwrapper.ssaBB->exprIds.back());
				if(lastExpr->type == HSSA_EXPR_JMP && lastExpr->subExpressions[0].type == HSSA_ARGTYPE_BLOCK){
					bbwrapper.outBlocks.push_back(lastExpr->subExpressions[0].uval);
				}else if(lastExpr->type == HSSA_EXPR_CJMP && lastExpr->subExpressions[1].type == HSSA_ARGTYPE_BLOCK){
					bbwrapper.outBlocks.push_back(lastExpr->subExpressions[1].uval);
				}
			}
			for(auto it = bbwrapper.ssaBB->exprIds.begin(); it != bbwrapper.ssaBB->exprIds.end(); ++it) {
				HId id = *it;
				HSSAExpression* expr = function->ssaRep.expressions.get(id);
				for(int i = 0; i < expr->subExpressions.size();i++){
					if(expr->subExpressions[i].type == H_ARGTYPE_REG && expr->subExpressions[i].id == 0){
						HRegister* reg = arch->getRegister(expr->subExpressions[i].reg);
						bool found = false;
						for(HSSARegDef& def : bbwrapper.outputs) {
							if(def.regId == reg->id) {
								expr->subExpressions[i].id = def.ssaId;
								found = true;
								break;
							}
						}
						if(!found){
							for(HSSARegDef& def : bbwrapper.outputs) {
								if(def.offset <= reg->offset && reg->offset + reg->size <= def.offset + def.size) {
									
									HSSAExpression newExpr;
									newExpr.type = HSSA_EXPR_SPLIT;
									newExpr.exprtype = HSSA_TYPE_UINT;
									newExpr.regId = reg->id;
									newExpr.subExpressions.add(HArgument::createReg(reg, def.ssaId));
									newExpr.subExpressions.add(HArgument::createVal(reg->offset - def.offset, arch->bitbase));
									newExpr.subExpressions.add(HArgument::createVal((def.offset + def.size) - (reg->offset + reg->size), arch->bitbase));
									
									HId newId = function->ssaRep.expressions.add(newExpr);
									it = bbwrapper.ssaBB->exprIds.insert(it, newId);
									
									expr = function->ssaRep.expressions.get(id);//reload expression in case we have a reallocate
									expr->subExpressions[i].id = newId;
									
									found = true;
									break;
								}
							}
						}
						if(!found){
							addRegDef(0, reg,&bbwrapper.inputs, false);
						}
					}
				}
				if(expr->regId){
					HRegister* reg = arch->getRegister(expr->regId);
					addRegDef(expr->id, reg, &bbwrapper.outputs, expr->type != HSSA_EXPR_UPDATEPART);
				}
			}
		}
		
	}
	
	void HSSAPhiNodeGenerator::doTransformation (HFunction* function){
		
		printf("Generating Phi-Nodes for Function at Address 0x%x\n", function->baseaddr);
		this->function = function;
		
		resolveRegs();
		
		for(BasicBlockWrapper& wrap : bbwrappers){
			
			for(HSSARegDef& regDef : wrap.inputs) {
				HId gatheredIds[bbwrappers.size()] = {0};
				uint64_t gatheredIdCount = 0;
				HId visitedBlocks[bbwrappers.size()] = {wrap.ssaBB->id};
				uint64_t visitedBlockCount = 1;
				bool visitedOrigin = false;
				
				HRegister* reg = arch->getRegister(regDef.regId);
				
				//printf("Searching Defs for Reg %s in Block %d\n", reg->name.cstr(), wrap.ssaBB->id);
				for(HId& inBlockId : wrap.inBlocks) {
					handleBBs(getWrapper(inBlockId), reg, gatheredIds, &gatheredIdCount, visitedBlocks, &visitedBlockCount, &visitedOrigin);
				}
				//printf("Reg: %s Count %d\n", reg->name.cstr(), gatheredIdCount);
				assert(gatheredIdCount);
				
				HSSAExpression phinode;
				phinode.type = gatheredIdCount == 1 ? HSSA_EXPR_ASSIGN : HSSA_EXPR_PHI;
				phinode.exprtype = HSSA_TYPE_UINT;
				phinode.regId = reg->id;
				phinode.size = reg->size;
				for(int i = 0; i < gatheredIdCount; i++){
					phinode.subExpressions.add(HArgument::createReg(reg, gatheredIds[i]));
				}
				HId exprId = function->ssaRep.expressions.add(phinode);
				wrap.ssaBB->exprIds.insert(wrap.ssaBB->exprIds.begin(), exprId);
				bool needInOutput = true;
				for(HSSARegDef& def : wrap.outputs){
					if(def.parentId == reg->parentId){
						needInOutput = false;
						break;
					}
				}
				if(needInOutput){
					addRegDef(exprId,reg, &wrap.outputs,true);
				}
			}
			//wrap.print(arch);
		}
		
		resolveRegs();
		for(BasicBlockWrapper& wrap : bbwrappers){
			wrap.print(arch);
		}
	}
	
	void HSSAPhiNodeGenerator::handleBBs(BasicBlockWrapper* wrapper, HRegister* reg,  HId* gatheredIds, uint64_t* gatheredIdCount, HId* visitedBlocks, uint64_t* visitedBlockCount, bool* visitedOrigin) {
		//printf("\nHandling Block %d\n", wrapper->ssaBB->id);
		
		//printf("Found no match on BB %d\n", wrapper->ssaBB->id);
		for(int i = 0; i < *visitedBlockCount; i++){
			if(visitedBlocks[i] == wrapper->ssaBB->id){
				if(i == 0){
					//printf("Visiting Origin\n");
					*visitedOrigin = true;
				}
				//printf("Already Visited BB %d\n", wrapper->ssaBB->id);
				return;
			}
		}
		visitedBlocks[(*visitedBlockCount)++] = wrapper->ssaBB->id;
		
		HSSARegDef* foundParentDef = nullptr;
		for(HSSARegDef& regDef : wrapper->outputs) {
			if(regDef.parentId == reg->parentId){
				if(regDef.regId == reg->id){
					gatheredIds[(*gatheredIdCount)++] = regDef.ssaId;
					//printf("\Found perfect Match %d\n", regDef.ssaId);
					return;
				}else if(regDef.regId == reg->parentId){
					//printf("\Found parent Match %d\n", regDef.ssaId);
					foundParentDef = &regDef;
				}
			}
		}
		if(foundParentDef){
			//printf("Found parent Match %d\n", foundParentDef->ssaId);
			HSSAExpression expr;
			expr.type = HSSA_EXPR_SPLIT;
			expr.exprtype = HSSA_TYPE_UINT;
			expr.size = reg->size;
			expr.regId = reg->id;
			expr.subExpressions.add(HArgument::createReg(arch->getRegister(foundParentDef->regId), foundParentDef->ssaId));
			expr.subExpressions.add(HArgument::createVal(reg->offset, arch->bitbase));
			expr.subExpressions.add(HArgument::createVal(reg->size, arch->bitbase));
			HId exprId = function->ssaRep.expressions.add(expr);
			wrapper->ssaBB->exprIds.push_back(exprId);
			addRegDef(exprId, reg, &wrapper->outputs, true);
			gatheredIds[(*gatheredIdCount)++] = exprId;
		}else{
			
			for(HId& inBlockId : wrapper->inBlocks) {
				BasicBlockWrapper* subwrapper = getWrapper(inBlockId);
				handleBBs(subwrapper, reg, gatheredIds, gatheredIdCount, visitedBlocks, visitedBlockCount, visitedOrigin);
			}
		}
	}
	
}
