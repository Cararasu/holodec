#ifndef SSAPEEPHOLEOPTIMIZER_H
#define SSAPEEPHOLEOPTIMIZER_H

#include "General.h"
#include "SSA.h"
#include "SSATransformer.h"
namespace holodec {

		
	struct HArgumentRef{
		HId argIndex;
		bool newArgument;
	};
	
	struct HExpressionRef{
		HArgumentRef exprRef;
		
		SSAExprType type = SSA_EXPR_INVALID;
		uint64_t size = 0;
		SSAType returntype = SSA_TYPE_UNKNOWN;
		union { //64 bit
			SSAFlagType flagType;
			SSAOpType opType;
			HId builtinId;
			HId instrId;
		};
		
	};
	
	struct MatchContext{
		std::vector<HId> expressionsMatched;
	};
	
	//Insert Instruction
	//Insert Argument
	//Copy Arguments
	//Replace Argument
	enum MatchActionType{
		MATCHACTION_INSERT_AS_ARG,
		MATCHACTION_INSERT_ARG,
		MATCHACTION_COPY_ARG,
		MATCHACTION_SET_EXPR_DATA,
		MATCHACTION_INHERIT_EXPR_DATA,
		MATCHACTION_INHERIT_ARG_SIZE,
	};
	struct MatchAction{
		MatchActionType actionType;
		HId createdExprIndex;
		HId foundExprIndex;
		HId argIndex;
		
		union{
			struct{
				SSAExprType type;
				SSAOpType opType = H_OP_INVALID;
				SSAFlagType flagType = SSA_FLAG_UNKNOWN;
			}expressionTypes;
			struct{
				uint64_t size = 0;
				SSAType type = SSA_TYPE_UNKNOWN;
				SSAExprLocation loc = SSA_LOCATION_NONE;
				Reference locRef = {0,0};
			}expressionData;
			struct{
				SSAArgTypes type = SSA_ARGTYPE_UNKN;
				uint32_t size = 0;
				ArgSInt sval = 0;
				ArgUInt uval = 0;
				ArgFloat fval = 0.0f;
				Reference ref = {0,0};
			}argInfos;
			struct{
				HId srcFoundExprId = 0;
				HId argumentIndex = 0;
				uint32_t argumentCount = 0;
			}copyArgs;
		};
		
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, SSAExprType type) :
			actionType(MATCHACTION_INSERT_AS_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			expressionTypes({type, H_OP_INVALID, SSA_FLAG_UNKNOWN}){}
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, SSAExprType type, SSAOpType opType) :
			actionType(MATCHACTION_INSERT_AS_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			expressionTypes({type, opType, SSA_FLAG_UNKNOWN}){}
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, SSAExprType type, SSAFlagType flagType) :
			actionType(MATCHACTION_INSERT_AS_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			expressionTypes({type, H_OP_INVALID, flagType}){}
			
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, uint32_t size, ArgSInt sval) : 
			actionType(MATCHACTION_INSERT_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			argInfos({SSA_ARGTYPE_SINT, size, sval, 0, 0.0f, {0, 0}}){}
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, uint32_t size, ArgUInt uval) : 
			actionType(MATCHACTION_INSERT_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			argInfos({SSA_ARGTYPE_SINT, size, 0, uval, 0.0f, {0, 0}}){}
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, uint32_t size, ArgFloat fval) : 
			actionType(MATCHACTION_INSERT_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			argInfos({SSA_ARGTYPE_SINT, size, 0, 0, fval, {0, 0}}){}
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, uint32_t size, Reference ref) : 
			actionType(MATCHACTION_INSERT_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			argInfos({SSA_ARGTYPE_SINT, size, 0, 0, 0.0f, ref}){}
			
		MatchAction(HId createdExprIndex, HId foundExprIndex, uint64_t size, SSAType type, SSAExprLocation loc, Reference locRef) : 
			actionType(MATCHACTION_SET_EXPR_DATA), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(0),
			expressionData({size, type, loc, locRef}){}
			
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, HId srcFoundExprId, HId argumentIndex, uint32_t argumentCount) : 
			actionType(MATCHACTION_COPY_ARG), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			copyArgs({srcFoundExprId, argumentIndex, argumentCount}){}
			
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId srcFoundExprId) : 
			actionType(MATCHACTION_INHERIT_EXPR_DATA), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(0),
			copyArgs({srcFoundExprId, 0, 0}){}
			
		MatchAction(HId createdExprIndex, HId foundExprIndex, HId argIndex, HId srcFoundExprId) : 
			actionType(MATCHACTION_INHERIT_ARG_SIZE), createdExprIndex(createdExprIndex), foundExprIndex(foundExprIndex), argIndex(argIndex),
			copyArgs({srcFoundExprId, 0, 0}){}
		
		HId doAction(SSARepresentation* rep, MatchContext* context, std::vector<HId>* createdExpressions);
		
	};
	enum MatchType{
		MATCH_TYPE = 1,
		MATCH_OPTYPE,
		MATCH_FLAGTYPE,
		
		MATCH_BUILTIN,
		MATCH_LOCATION,
		
		MATCH_ARGUMENTTYPE,
		MATCH_ARGUMENTVALUE,
	};
	struct Matcher{
		MatchType matchType;
		union{
			struct{
				SSAExprType type;
				SSAOpType opType;
				SSAFlagType flagType;
				uint64_t size;
			} type;
			struct{
				HId index;
				SSAArgTypes type;
				union{
					ArgSInt sval;
					ArgUInt uval;
					ArgFloat fval;
					Reference ref;
				}value;
			} argument;
			struct{
				HId id;
			} builtin;
			struct{
				SSAExprLocation loc;
				Reference ref;
			} location;
		};
		Matcher(SSAExprType exprType, uint64_t size = 0): matchType(MATCH_TYPE){
			type.type = exprType;
			type.size = size;
		}
		Matcher(SSAExprType exprType, SSAOpType opType, uint64_t size = 0): matchType(MATCH_OPTYPE){
			type.type = exprType;
			type.opType = opType;
			type.size = size;
		}
		Matcher(SSAExprType exprType, SSAFlagType flagType, uint64_t size = 0): matchType(MATCH_FLAGTYPE){
			type.type = exprType;
			type.flagType = flagType;
			type.size = size;
		}
		Matcher(HId argIndex, SSAArgTypes argtype): matchType(MATCH_ARGUMENTTYPE){
			argument.index = argIndex;
			argument.type = argtype;
		}
		Matcher(HId argIndex, ArgSInt sval): matchType(MATCH_ARGUMENTVALUE){
			argument.index = argIndex;
			argument.type = SSA_ARGTYPE_SINT;
		}
		Matcher(HId argIndex, ArgUInt uval): matchType(MATCH_ARGUMENTVALUE){
			argument.index = argIndex;
			argument.type = SSA_ARGTYPE_UINT;
		}
		Matcher(HId argIndex, ArgFloat fval): matchType(MATCH_ARGUMENTVALUE){
			argument.index = argIndex;
			argument.type = SSA_ARGTYPE_FLOAT;
		}
		Matcher(HId id): matchType(MATCH_BUILTIN){
			builtin.id = id;
		}
		Matcher(SSAExprLocation loc, Reference ref): matchType(MATCH_LOCATION){
			location.loc = loc;
			location.ref = ref;
		}
		
		bool match(SSAExpression* expression);
	};
	struct ExprMatcher{
		HId subexprIndex;
		HList<Matcher> matchers;
		HList<ExprMatcher> subMatchers;
		HList<MatchAction> actions;
		
		ExprMatcher(HId subexprIndex, HList<Matcher> matchers, HList<ExprMatcher> subMatchers, HList<MatchAction> actions = HList<MatchAction>()) : 
			subexprIndex(subexprIndex), matchers(matchers), subMatchers(subMatchers), actions(actions) {}
		
		bool match(SSARepresentation* rep, SSAExpression* expr, MatchContext* context);
	};
	
	
	struct SSAPeepholeOptimizer : public SSATransformer {
		
		HList<ExprMatcher> matchers;
		
		SSAPeepholeOptimizer();
		
		virtual void doTransformation (Function* function);
	};

}

#endif // SSAPEEPHOLEOPTIMIZER_H
