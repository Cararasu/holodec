#include "HSSACallingConvApplier.h"
#include "HCallingConvention.h"
#include "HArchitecture.h"

namespace holodec{
	
	void HSSACallingConvApplier::doTransformation (HFunction* function){
		
		HCallingConvention* cc = arch->getCallingConvention(function->callingconvention);
		
		for(HSSAExpression& expr : function->ssaRep.expressions){
			if(expr.type == HSSA_EXPR_CALL){
				bool isParam = false;
				for(HString& regStr : cc->callerSaved){
					HRegister* reg = arch->getRegister(regStr);
					if(expr.id == reg->id){
						//leave the arg
						isParam = true;
					}
				}
				for(int i = 0; i < H_CC_PARA_MAX; i++){
					for(int j = 0; j < H_CC_MAX_ARGS; j++){
						if(cc->parameters[i][j]){
							HRegister* reg = arch->getRegister(cc->parameters[i][j]);
							if(expr.id == reg->id){
								//leave the arg
								isParam = true;
								break;
							}
						}
					}
				}
				if(!isParam){
					//remove from arg list
				}
			}
			if(expr.type == HSSA_EXPR_OUTPUT){
				bool isParam = false;
				for(HString& regStr : cc->callerSaved){
					HRegister* reg = arch->getRegister(regStr);
					if(expr.id == reg->id){
						//make an assignment
						isParam = true;
					}
				}
				for(int i = 0; i < H_CC_PARA_MAX; i++){
					for(int j = 0; j < H_CC_MAX_ARGS; j++){
						if(cc->returns[i][j]){
							HRegister* reg = arch->getRegister(cc->returns[i][j]);
							if(expr.id == reg->id){
								//leave as return
								isParam = true;
							}
						}
					}
				}
				if(!isParam){
					expr.type = HSSA_EXPR_UNDEF;
				}
			}
			if(expr.type == HSSA_EXPR_RETURN){
				bool isParam = false;
				for(int i = 0; i < H_CC_PARA_MAX; i++){
					for(int j = 0; j < H_CC_MAX_ARGS; j++){
						if(cc->returns[i][j]){
							HRegister* reg = arch->getRegister(cc->returns[i][j]);
							if(expr.id == reg->id){
								//leave as arg
								isParam = true;
							}
						}
					}
				}
				if(!isParam){
					//remove arg
				}
			}
			if(expr.type == HSSA_EXPR_INPUT){
				bool isParam = false;
				for(int i = 0; i < H_CC_PARA_MAX; i++){
					for(int j = 0; j < H_CC_MAX_ARGS; j++){
						if(cc->parameters[i][j]){
							HRegister* reg = arch->getRegister(cc->parameters[i][j]);
							if(expr.id == reg->id){
								expr.subExpressions.add(HArgument::createVal((uint64_t)i,arch->bitbase));
								isParam = true;
								break;
							}
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