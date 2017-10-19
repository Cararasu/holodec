
#include "HSSAAddressToBlockTransformer.h"
#include "HSSA.h"
#include "HFunction.h"


namespace holodec {

	void HSSAAddressToBlockTransformer::parseBlock (HSSABB* block) {
		if(block->exprIds.size())
			if(function->ssaRep.expressions[block->exprIds.back()].type == HSSA_EXPR_RETURN)//if last statement is return then we do nothing
				return;
		if(!block->fallthroughId){
			for(HSSABB& bb : function->ssaRep.bbs){
				if(bb.startaddr == block->endaddr){
					block->fallthroughId = bb.id;
					block->outBlocks.insert(bb.id);
					bb.inBlocks.insert(block->id);
					break;
				}
			}
		}
	}
	void HSSAAddressToBlockTransformer::parseExpression (HSSABB* basicBlock, HSSAExpression* expression) {
		
		if(expression->type == HSSA_EXPR_JMP){
			if(expression->subExpressions[0].type == HIR_ARGTYPE_UINT){
				for(HSSABB& bb : function->ssaRep.bbs){
					if(bb.startaddr == expression->subExpressions[0].uval){
						expression->subExpressions[0] = HSSAArgument::createBlock(bb.id);
						basicBlock->outBlocks.insert(bb.id);
						bb.inBlocks.insert(bb.id);
						break;
					}
				}
			}
		}else if(expression->type == HSSA_EXPR_CJMP){
			if(expression->subExpressions[1].type == HIR_ARGTYPE_UINT){
				for(HSSABB& bb : function->ssaRep.bbs){
					if(bb.startaddr == expression->subExpressions[1].uval){
						expression->subExpressions[1] = HSSAArgument::createBlock(bb.id);
						basicBlock->outBlocks.insert(bb.id);
						bb.inBlocks.insert(bb.id);
						break;
					}
				}
			}
		}else if(expression->type == HSSA_EXPR_MULTIBR){
			for(auto it = expression->subExpressions.begin() + 1; it != expression->subExpressions.end(); ++it){
				if(it->type == HIR_ARGTYPE_UINT){
					for(HSSABB& bb : function->ssaRep.bbs){
						if(bb.startaddr == it->uval){
							*it = HSSAArgument::createBlock(bb.id);
							basicBlock->outBlocks.insert(bb.id);
							bb.inBlocks.insert(bb.id);
							break;
						}
					}
				}
			}
		}
	}
}
