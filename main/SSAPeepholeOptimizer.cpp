#include "SSAPeepholeOptimizer.h"
#include "Function.h"

namespace holodec {


	HId MatchAction::doAction (SSARepresentation* rep, MatchContext* context, std::vector<HId>* createdExpressions) {
		HId expressionId;
		if (createdExprIndex) {
			expressionId = createdExpressions->at (createdExprIndex - 1);
		} else if (foundExprIndex) {
			expressionId = context->expressionsMatched[foundExprIndex - 1];
		} else {
			return 0;
		}
		SSAExpression& expr = rep->expressions[expressionId];
		switch (actionType) {
		case MATCHACTION_INSERT_AS_ARG: {
			SSAExpression expression;
			expression.type = expressionTypes.type;
			if (expressionTypes.type == SSA_EXPR_OP)
				expression.opType = expressionTypes.opType;
			if (expressionTypes.type == SSA_EXPR_FLAG)
				expression.flagType = expressionTypes.flagType;
			rep->expressions.push_back (expression);
			HId newExpressionId = rep->expressions.back().id;
			for (SSABB& bb : rep->bbs) {
				for (auto it = bb.exprIds.begin(); it != bb.exprIds.end(); ++it) {
					if (*it == expressionId) {
						bb.exprIds.insert (it, newExpressionId);
						if (argIndex) {
							expr.subExpressions[argIndex - 1] = SSAArgument::createId (newExpressionId, 0);
						} else {
							expr.subExpressions.push_back (SSAArgument::createId (newExpressionId, 0));
						}
						createdExpressions->push_back (newExpressionId);
						return newExpressionId;
					}
				}
			}
		}
		break;
		case MATCHACTION_INSERT_ARG: {
			SSAArgument argument;
			argument.type = argInfos.type;
			switch (argument.type) {
			case SSA_ARGTYPE_SINT:
				argument.sval = argInfos.sval;
				break;
			case SSA_ARGTYPE_UINT:
				argument.uval = argInfos.uval;
				break;
			case SSA_ARGTYPE_FLOAT:
				argument.fval = argInfos.fval;
				break;
			default:
				argument.ref = argInfos.ref;
			}
			expr.subExpressions.push_back (argument);
		}
		break;
		case MATCHACTION_COPY_ARG:
			if (copyArgs.srcFoundExprId && copyArgs.srcFoundExprId <= context->expressionsMatched.size()) {
				HId srcExprId = context->expressionsMatched[copyArgs.srcFoundExprId - 1];
				SSAExpression& srcExpr = rep->expressions[srcExprId];
				expr.subExpressions.insert (
				    expr.subExpressions.end(),
				    srcExpr.subExpressions.begin() + (copyArgs.argumentIndex - 1),
				    srcExpr.subExpressions.begin() + (copyArgs.argumentIndex + copyArgs.argumentCount - 1));
			}
			break;
		case MATCHACTION_INHERIT_EXPR_DATA:
			if (copyArgs.srcFoundExprId && copyArgs.srcFoundExprId <= context->expressionsMatched.size()) {
				HId srcExprId = context->expressionsMatched[copyArgs.srcFoundExprId - 1];
				SSAExpression& srcExpr = rep->expressions[srcExprId];

				expr.size = srcExpr.size;
				expr.returntype = srcExpr.returntype;
				expr.location = srcExpr.location;
				expr.locref = srcExpr.locref;
			}
			break;
		case MATCHACTION_INHERIT_ARG_SIZE:
			if (copyArgs.srcFoundExprId && copyArgs.srcFoundExprId <= context->expressionsMatched.size()) {
				HId srcExprId = context->expressionsMatched[copyArgs.srcFoundExprId - 1];
				SSAExpression& srcExpr = rep->expressions[srcExprId];
				SSAArgument* dstArg;
				if (argIndex)
					dstArg = &expr.subExpressions[argIndex - 1];
				else
					dstArg = &expr.subExpressions.back();
				dstArg->size = srcExpr.size;
			}
			break;
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
			std::vector<HId> createdExprs;
			for (MatchAction& action : actions) {
				action.doAction (rep, context, &createdExprs);
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
			{Matcher (SSA_EXPR_FLAG, SSA_FLAG_C) },
			{}
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
					MatchAction (0, 1, 0, SSA_EXPR_CAST),
					MatchAction (1, 0, 0, SSA_EXPR_CAST),
					//set the data of the first created to the 
					MatchAction (1, 0, 1),
					MatchAction (2, 0, 1),
					//createdId, foundId, argIndex: copy arg from foundId 1
					MatchAction (0, 1, 0, 1)
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
