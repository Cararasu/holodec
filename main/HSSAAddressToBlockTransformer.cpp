
#include "HSSAAddressToBlockTransformer.h"
#include "HSSA.h"
#include "HFunction.h"


namespace holodec {

	void HSSAAddressToBlockTransformer::parseBlock (HSSABB* block) {
		if(block->exprIds.size())
			if(function->ssaRep.expressions[block->exprIds.back()].type == HSSA_EXPR_RETURN)//if last statement is return then we do nothing
				return;
		for(HSSABB& bb : function->ssaRep.bbs){
			if(bb.startaddr == block->endaddr){
				block->fallthroughId = bb.id;
				break;
			}
		}
	}
	void HSSAAddressToBlockTransformer::parseExpression (HSSAExpression* expression) {
		
		if(expression->type == HSSA_EXPR_JMP){
			if(expression->subExpressions[0].type == H_ARGTYPE_UINT){
				for(HSSABB& bb : function->ssaRep.bbs){
					if(bb.startaddr == expression->subExpressions[0].uval){
						expression->subExpressions[0] = HArgument::createIndex(HSSA_ARGTYPE_BLOCK, bb.id);
						break;
					}
				}
			}
		}else if(expression->type == HSSA_EXPR_CJMP){
			if(expression->subExpressions[1].type == H_ARGTYPE_UINT){
				for(HSSABB& bb : function->ssaRep.bbs){
					if(bb.startaddr == expression->subExpressions[1].uval){
						expression->subExpressions[1] = HArgument::createIndex(HSSA_ARGTYPE_BLOCK, bb.id);
						break;
					}
				}
			}
		}
	}
}
