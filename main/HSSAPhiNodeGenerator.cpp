#include "HSSAPhiNodeGenerator.h"
#include "HFunction.h"
#include "HArchitecture.h"

namespace holodec {

	struct BasicBlockWrapper{
		HSSABB* ssaBB;
		
		HList<HId> inBlocks;
		HList<HId> outBlocks;
		
		HList<HSSARegDef> inputs;
		HList<HSSARegDef> outputs;
		
		void print(HArchitecture* arch) {
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
	};
	
	
	void addRegDef(HId id, HRegister* reg, HList<HSSARegDef>* list){
		bool rep = false;
		for(auto it = list->begin(); it != list->end();){
			HSSARegDef& def = *it;
			if(def.parentId == reg->parentId){
				if(reg->clearParentOnWrite){
					if(rep){
						list->erase(it);
						continue;
					}else{
						def.ssaId = id;
						def.regId = reg->id;
						rep = true;
					}
				}else{
					if(def.regId == reg->id || (reg->offset <= def.offset && def.offset + def.size <= reg->offset + reg->size)){
						if(rep){
							list->erase(it);
							continue;
						}else{
							def.ssaId = id;
							def.regId = reg->id;
							rep = true;
						}
					}
				}
			}
			++it;
		}
		if(!rep)
			list->push_back({id,reg->id, reg->parentId, reg->size, reg->offset});
	}
	
	void HSSAPhiNodeGenerator::doTransformation (HFunction* function){
		
		printf("Generating Phi-Nodes for Function at Address 0x%x\n", function->baseaddr);
		
		HList<BasicBlockWrapper> bbwrappers;
		
		for(HSSABB& bb : function->ssaRep.bbs){
			
			BasicBlockWrapper bbwrapper;
			bbwrapper.ssaBB = &bb;
			
			for(HSSABB& bb2 : function->ssaRep.bbs){
				if(bb.id == bb2.fallthroughId){
					bbwrapper.inBlocks.push_back(bb2.id);
				}
				if(bb2.exprIds.size()){
					HSSAExpression* lastExpr = function->ssaRep.expressions.get(bb2.exprIds.back());
					if(lastExpr->type == HSSA_EXPR_JMP && lastExpr->subExpressions[0].type == HSSA_ARGTYPE_BLOCK){
						if(bb.id == lastExpr->subExpressions[0].uval){
							bbwrapper.inBlocks.push_back(bb2.id);
						}
					}else if(lastExpr->type == HSSA_EXPR_CJMP && lastExpr->subExpressions[1].type == HSSA_ARGTYPE_BLOCK){
						if(bb.id == lastExpr->subExpressions[1].uval){
							bbwrapper.inBlocks.push_back(bb2.id);
						}
					}
				}
			}
			if(bb.fallthroughId)
				bbwrapper.outBlocks.push_back(bb.fallthroughId);
			if(bb.exprIds.size()){
				HSSAExpression* lastExpr = function->ssaRep.expressions.get(bb.exprIds.back());
				if(lastExpr->type == HSSA_EXPR_JMP && lastExpr->subExpressions[0].type == HSSA_ARGTYPE_BLOCK){
					bbwrapper.outBlocks.push_back(lastExpr->subExpressions[0].uval);
				}else if(lastExpr->type == HSSA_EXPR_CJMP && lastExpr->subExpressions[1].type == HSSA_ARGTYPE_BLOCK){
					bbwrapper.outBlocks.push_back(lastExpr->subExpressions[1].uval);
				}
			}
			for(HId& id : bb.exprIds){
				HSSAExpression* expr = function->ssaRep.expressions.get(id);
				if(expr->regId){
					HRegister* reg = arch->getRegister(expr->regId);
					addRegDef(expr->id, reg, &bbwrapper.outputs);
				}
				for(int i = 0; i < expr->subExpressions.size();i++){
					if(expr->subExpressions[i].type == H_ARGTYPE_REG){
						HRegister* reg = arch->getRegister(expr->subExpressions[i].reg);
						bool found = false;
						for(HSSARegDef& def : bbwrapper.outputs) {
							if(def.parentId == reg->parentId && (def.offset <= reg->offset && reg->offset + reg->size <= def.offset + def.size)){
								found = true;
								break;
							}
						}
						
						if(!found)
							addRegDef(0, reg,&bbwrapper.inputs);
					}
				}
			}
			bbwrappers.push_back(bbwrapper);
		}
		for(BasicBlockWrapper& wrap : bbwrappers){
			wrap.print(arch);
		}
	}
}
