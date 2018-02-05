
#include "SSAAddressToBlockTransformer.h"
#include "SSA.h"
#include "Function.h"
#include "Architecture.h"


namespace holodec {

	void SSAAddressToBlockTransformer::parseBlock (SSABB* block) {
		if(block->exprIds.size())
			if(function->ssaRep.expressions[block->exprIds.back()].type == SSAExprType::eReturn)//if last statement is return then we do nothing
				return;
		if(!block->fallthroughId){
			for(SSABB& bb : function->ssaRep.bbs){
				if(bb.startaddr == block->endaddr){
					block->fallthroughId = bb.id;
					block->outBlocks.insert(bb.id);
					bb.inBlocks.insert(block->id);
					break;
				}
			}
		}
	}
	HList<HId>::iterator SSAAddressToBlockTransformer::parseExpression (SSABB* basicBlock, HList<HId>::iterator it) {
		
		SSAExpression* expression = &function->ssaRep.expressions[*it];
		
		if(expression->type == SSAExprType::eJmp || expression->type == SSAExprType::eCJmp){
			if(expression->subExpressions[0].type == SSAArgType::eUInt){
				for(SSABB& bb : function->ssaRep.bbs){
					if(bb.startaddr == expression->subExpressions[0].uval){
						expression->subExpressions[0] = SSAArgument::createBlock(bb.id);
						basicBlock->outBlocks.insert(bb.id);
						bb.inBlocks.insert(basicBlock->id);
						break;
					}
				}
			}else{
				if (expression->subExpressions[0].type == SSAArgType::eId) {
					SSAExpression& loadExpr = function->ssaRep.expressions[expression->subExpressions[0].ssaId];
					if (loadExpr.type == SSAExprType::eLoad) {
						uint64_t baseaddr;
						if (function->ssaRep.calcConstValue(loadExpr.subExpressions[0], &baseaddr)) {
							if (arch->bitbase < sizeof(uint64_t) * 8)
								baseaddr %= (1 << arch->bitbase);

							Symbol* sym = binary->findSymbol(baseaddr, &SymbolType::symdynfunc);
							if (sym) {
								sym->print();
							}
						}
					}
				}
				for(Register& reg : arch->registers){
					if(!reg.id || reg.directParentRef)
						continue;
					expression->subExpressions.push_back(SSAArgument::createReg(&reg, 0));
				}
			}
		}else if(expression->type == SSAExprType::eMultiBranch){
			for(auto it = expression->subExpressions.begin() + 1; it != expression->subExpressions.end(); ++it){
				if(it->type == SSAArgType::eUInt){
					for(SSABB& bb : function->ssaRep.bbs){
						if(bb.startaddr == it->uval){
							*it = SSAArgument::createBlock(bb.id);
							basicBlock->outBlocks.insert(bb.id);
							bb.inBlocks.insert(basicBlock->id);
							break;
						}
					}
				}
			}
		}
		return it;
	}
}
