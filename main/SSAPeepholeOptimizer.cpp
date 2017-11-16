#include "SSAPeepholeOptimizer.h"
#include "Function.h"
#include <cassert>
#include <algorithm>

namespace holodec {


	void MatchAction::doAction (SSARepresentation* rep, MatchContext* context) {
		HId srcExpressionId = 0;
		SSAExpression* srcExpr = nullptr;
		if(src.createExprIndex){
			srcExpressionId = context->expressionsCreated.at (src.createExprIndex - 1);
			srcExpr = &rep->expressions[srcExpressionId];
		}else if(src.foundExprIndex){
			srcExpressionId = context->expressionsMatched[src.foundExprIndex - 1];
			srcExpr = &rep->expressions[srcExpressionId];
		}
		HId dstExpressionId = 0;
		SSAExpression* dstExpr = nullptr;
		if(dst.createExprIndex){
			dstExpressionId = context->expressionsCreated.at (dst.createExprIndex - 1);
			dstExpr = &rep->expressions[dstExpressionId];
		}else if(dst.foundExprIndex){
			dstExpressionId = context->expressionsMatched[dst.foundExprIndex - 1];
			dstExpr = &rep->expressions[dstExpressionId];
		}
		
		switch (actionType) {
		case MATCHACTION_INVALID:
			return;
		case MATCHACTION_INHERIT_INSTR:{
			assert(srcExpr && dstExpr);
			if(inheritInstrFlags & MATCHACTION_INHERIT_INSTR_SIZE)
				dstExpr->size = srcExpr->size;
			if(inheritInstrFlags & MATCHACTION_INHERIT_INSTR_LOCATION){
				dstExpr->location = srcExpr->location;
				dstExpr->locref = srcExpr->locref;
			}
			if(inheritInstrFlags & MATCHACTION_INHERIT_INSTR_ADDR)
				dstExpr->instrAddr = srcExpr->instrAddr;
			if(inheritInstrFlags & MATCHACTION_INHERIT_INSTR_EXPRTYPE)
				dstExpr->returntype = srcExpr->returntype;
		}return;
		case MATCHACTION_INHERIT_ARG:{
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			assert(dst.argIndex);
			if(inheritArgFlags & MATCHACTION_INHERIT_ARG_SIZE)
				dstExpr->subExpressions[dstIndex - 1].size = srcExpr->size;
			if(inheritArgFlags & MATCHACTION_INHERIT_ARG_LOCATION){
				switch(srcExpr->location){
				case SSA_LOCATION_REG:
				case SSA_LOCATION_STACK:
				case SSA_LOCATION_MEM:{
					dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_REG;
					dstExpr->subExpressions[dstIndex - 1].ref = srcExpr->locref;
				}break;
				}
			}
		}return;
		case MATCHACTION_INHERIT_ARGS:{
			HId srcIndex = src.argIndex ? src.argIndex : srcExpr->subExpressions.size();
			srcIndex = std::max(srcIndex, (HId)1);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size() + 1/*Adjust so that we insert really at the end*/;
			dstIndex = std::max(dstIndex, (HId)1);
			
			uint32_t count = size;
			if(!count)//all indices
				count = srcExpr->subExpressions.size() - srcIndex;
			dstExpr->subExpressions.insert(dstExpr->subExpressions.begin() + (dstIndex - 1), srcExpr->subExpressions.begin() + (srcIndex - 1), srcExpr->subExpressions.begin() + (srcIndex - 1) + count);
			
		}return;
		case MATCHACTION_INSTR_INSERT_AS_ARG:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size() + 1/*Adjust so that we insert really at the end*/;
			dstIndex = std::max(dstIndex, (HId)1);
			
			SSAExpression expression;
			rep->expressions.push_back(expression);
			SSAExpression& createdExpression = rep->expressions.back();
			context->expressionsCreated.push_back(createdExpression.id);
			
			SSAArgument arg;
			arg.type = SSA_ARGTYPE_ID;
			arg.ssaId = createdExpression.id;
			
			dstExpr->subExpressions.insert(dstExpr->subExpressions.begin() + (dstIndex - 1), arg);
			
			SSABB* foundBB = nullptr;
			for(SSABB& bb : rep->bbs){
				for(auto it = bb.exprIds.begin(); it != bb.exprIds.end(); it++){
					if(*it == dstExpressionId){
						bb.exprIds.insert(it,createdExpression.id);
						foundBB = &bb;
						return;
					}
				}
				if(foundBB)
					break;
			}
			assert(false);
			
		}return;
		case MATCHACTION_INSTR_TYPE:{
			dstExpr->type = types.type;
			if(types.flagType)
				dstExpr->flagType = types.flagType;
			if(types.opType)
				dstExpr->opType = types.opType;
		}return;
		case MATCHACTION_INSTR_EXPRTYPE:{
			dstExpr->returntype = exprType;
		}return;
		case MATCHACTION_INSTR_SIZE:{
			dstExpr->size = size;
		}return;
		case MATCHACTION_INSTR_BUILTIN:{
			dstExpr->builtinId = builtinId;
		}return;
		case MATCHACTION_ARG_SIZE:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].size = size;
		}return;
		case MATCHACTION_ARG_SVAL:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_SINT;
			dstExpr->subExpressions[dstIndex - 1].sval = sval;
		}return;
		case MATCHACTION_ARG_UVAL:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_UINT;
			dstExpr->subExpressions[dstIndex - 1].uval = uval;
		}return;
		case MATCHACTION_ARG_FVAL:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_FLOAT;
			dstExpr->subExpressions[dstIndex - 1].fval = fval;
		}return;
		case MATCHACTION_ARG_MEM:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_MEM;
			dstExpr->subExpressions[dstIndex - 1].ref = ref;
		}return;
		case MATCHACTION_ARG_STACK:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_STACK;
			dstExpr->subExpressions[dstIndex - 1].ref = ref;
		}return;
		case MATCHACTION_ARG_REG:{
			assert(dstExpressionId);
			HId dstIndex = dst.argIndex ? dst.argIndex : dstExpr->subExpressions.size();
			dstIndex = std::max(dstIndex, (HId)1);
			
			dstExpr->subExpressions[dstIndex - 1].type = SSA_ARGTYPE_REG;
			dstExpr->subExpressions[dstIndex - 1].ref = ref;
		}return;
		}
	}

	bool Matcher::match (SSAExpression* expression) {
		switch (matchType) {
		case MATCH_TYPE:
			return expression->type == type.type;
		case MATCH_OPTYPE:
			return expression->type == type.type && expression->opType == type.opType;
		case MATCH_FLAGTYPE:
			return expression->type == type.type && expression->flagType == type.flagType;

		case MATCH_BUILTIN:
			return expression->type == SSA_EXPR_BUILTIN && expression->builtinId == builtin.id;
		case MATCH_LOCATION:
			return expression->location == location.loc && expression->locref == location.ref;

		case MATCH_ARGUMENTTYPE:
			if (!argument.index || argument.index > expression->subExpressions.size())
				return false;
			{
				SSAArgument& arg = expression->subExpressions[argument.index - 1];
				return arg.type == argument.type;
			}
		case MATCH_ARGUMENTVALUE:
			if (!argument.index || argument.index > expression->subExpressions.size())
				return false;
			{
				SSAArgument& arg = expression->subExpressions[argument.index - 1];
				if (arg.type != argument.type)
					return false;
				switch (arg.type) {
				case SSA_ARGTYPE_SINT:
					return arg.sval == argument.value.sval;
				case SSA_ARGTYPE_UINT:
					return arg.uval == argument.value.uval;
				case SSA_ARGTYPE_FLOAT:
					return arg.fval == argument.value.fval;
				}
				return false;
			}
		}
		return false;
	}

	bool ExprMatcher::match (SSARepresentation* rep, SSAExpression* expr, MatchContext* context) {
		if (subexprIndex) {
			if (subexprIndex > expr->subExpressions.size())
				return false;
			if (HId subExpressionId = expr->subExpressions[subexprIndex - 1].ssaId)
				expr = & (rep->expressions[subExpressionId]);
		}
		for (Matcher& matcher : matchers) {
			if (!matcher.match (expr))
				return false;
		}
		context->expressionsMatched.push_back (expr->id);
		bool matched = true;
		for (ExprMatcher& subMatcher : subMatchers) {
			if (!subMatcher.match (rep, expr, context)) {
				matched = false;
				break;
			}
		}
		if (matched) {
			for (MatchAction& action : actions) {
				action.doAction (rep, context);
			}
		}
		context->expressionsMatched.pop_back();
		return false;
	}

	SSAPeepholeOptimizer::SSAPeepholeOptimizer() {
		ExprMatcher matcher (
		    0,
		{Matcher (SSA_EXPR_CJMP) }, {
			ExprMatcher (
			    1,
			{Matcher (SSA_EXPR_FLAG, SSA_FLAG_Z) },
			{},
			{
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0}),
				createInsertInstrAction({0,2,0})
				}
			)
		}
		);
		SSAExpression exprTemp;
		exprTemp.type = SSA_EXPR_CAST;
		matchers.push_back (matcher);
		matchers.push_back (
		    ExprMatcher (
		        0, {Matcher (SSA_EXPR_JMP) },
				{}, {
					//createdId, foundId, argIndex: create
					createInsertInstrAction({0,1,0}),
					createInsertInstrAction({1,0,0}),
					createInstrTypeAction({1,0,0},SSA_EXPR_CAST),
					createInstrTypeAction({2,0,0},SSA_EXPR_CAST),
					//inherit data
					createInheritInstrAction({0,1,0},{1,0,0}, 0),
					createInheritInstrAction({0,1,0},{2,0,0}, 0),
					
					//createdId, foundId, argIndex: copy arg from foundId 1
					createInheritArgsAction({0,1,0},{1,0,0}, 1)
				}
		    )
		);
	}
	void SSAPeepholeOptimizer::doTransformation (Function* function) {
		//Lets see what we need to make this work

		SSARepresentation& rep = function->ssaRep;
		for (SSABB& bb : rep.bbs) {

			for (HId exprId : bb.exprIds) {
				for (ExprMatcher& matcher : matchers) {
					MatchContext context;
					matcher.match (&rep, rep.expressions.get (exprId), &context);
				}
			}
		}

	}

}
