#include "HSSACallingConvApplier.h"
#include "HCallingConvention.h"
#include "HArchitecture.h"

namespace holodec{
	
	void HSSACallingConvApplier::doTransformation (HFunction* function){
		
		HCallingConvention* cc = arch->getCallingConvention(function->callingconvention);
		
		for(HSSAExpression& expr : function->ssaRep.expressions){
			if(expr.type == HSSA_EXPR_CALL){
				
			}
			if(expr.type == HSSA_EXPR_OUTPUT){
				
			}
			if(expr.type == HSSA_EXPR_RETURN){
				
			}
			if(expr.type == HSSA_EXPR_INPUT){
				bool isParam = false;
				for(int i = 0; i < H_CC_MAX_ARGS; i++){
					if(cc->parameters[H_CC_PARA_INT][i]){
						HRegister* reg = arch->getRegister(cc->parameters[H_CC_PARA_INT][i]);
						if(expr.regId == reg->id){
							expr.exprtype = HSSA_TYPE_INT;
							expr.subExpressions.add(HArgument::createVal((uint64_t)i,arch->bitbase));
							isParam = true;
							break;
						}
					}
					if(cc->parameters[H_CC_PARA_FLOAT][i]){
						HRegister* reg = arch->getRegister(cc->parameters[H_CC_PARA_FLOAT][i]);
						if(expr.regId == reg->id){
							expr.exprtype = HSSA_TYPE_FLOAT;
							expr.subExpressions.add(HArgument::createVal((uint64_t)i,arch->bitbase));
							isParam = true;
							break;
						}
					}
					if(cc->parameters[H_CC_PARA_VEC128][i]){
						HRegister* reg = arch->getRegister(cc->parameters[H_CC_PARA_VEC128][i]);
						if(expr.regId == reg->id){
							expr.exprtype = HSSA_TYPE_FLOAT;
							expr.subExpressions.add(HArgument::createVal((uint64_t)i,arch->bitbase));
							isParam = true;
							break;
						}
					}
					if(cc->parameters[H_CC_PARA_VEC256][i]){
						HRegister* reg = arch->getRegister(cc->parameters[H_CC_PARA_VEC256][i]);
						if(expr.regId == reg->id){
							expr.exprtype = HSSA_TYPE_FLOAT;
							expr.subExpressions.add(HArgument::createVal((uint64_t)i,arch->bitbase));
							isParam = true;
							break;
						}
					}
				}
				if(!isParam){
					expr.type = HSSA_EXPR_UNDEF;
				}
			}
		}
		
		
	}
}