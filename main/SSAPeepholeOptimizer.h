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
		std::vector<HId> expressionsCreated;
	};
	
	//inherit: expr-type, size, write-location, instrAddress
	//write: type, size, argument(id, sval, uval, fval)
	
	/*
		 * Argument
		HId ssaId = 0;
		SSAArgTypes type = SSA_ARGTYPE_UNKN;
		uint32_t size = 0;
		union {
			ArgSInt sval;
			ArgUInt uval;
			ArgFloat fval;
			Reference ref;
		};
	 * 
	 */
	
	//Insert Instruction
	//Insert Argument
	//Copy Arguments
	//Replace Argument
	
	enum MatchActionInheritInstrBits{
		MATCHACTION_INHERIT_INSTR_SIZE = 0x1,
		MATCHACTION_INHERIT_INSTR_LOCATION = 0x2,
		MATCHACTION_INHERIT_INSTR_ADDR = 0x4,
		MATCHACTION_INHERIT_INSTR_EXPRTYPE = 0x8,
	};
	enum MatchActionInheritArgBits{
		MATCHACTION_INHERIT_ARG_SIZE = 0x1,
		MATCHACTION_INHERIT_ARG_LOCATION = 0x2,
	};
	
	enum MatchCompareType{
		MATCHCOMPARE_INSTR_SIZE = 1,
		MATCHCOMPARE_INSTR_TYPE,
		MATCHCOMPARE_INSTR_EXPRTYPE,
		MATCHCOMPARE_INSTR_BUILTIN,
		MATCHCOMPARE_ARG_SIZE,
		MATCHCOMPARE_ARG_SVAL,
		MATCHCOMPARE_ARG_UVAL,
		MATCHCOMPARE_ARG_FVAL,
	};
	enum MatchActionType{
		MATCHACTION_INVALID = 0,
		MATCHACTION_INHERIT_INSTR = 1,
		//src, dst
		MATCHACTION_INHERIT_ARG,
		//src, dst, dst-arg
		
		MATCHACTION_INHERIT_ARGS,//inherit[args](f1,1,1,c1,1)
		//src, src-arg, src-argcount
		//dst, dst-arg
		
		MATCHACTION_INSTR_INSERT_AS_ARG,//instr[insert-arg]()
		//dst, dst-arg
		
		MATCHACTION_INSTR_TYPE,
		//type, flagtype, optype, dst
		MATCHACTION_INSTR_SIZE,
		MATCHACTION_INSTR_EXPRTYPE,
		//exprtype, dst
		MATCHACTION_INSTR_BUILTIN,
		//builtinId, dst
		
		MATCHACTION_ARG_SIZE,
		//dst, dst-arg, size
		MATCHACTION_ARG_SVAL,
		//dst, dst-arg, sval
		MATCHACTION_ARG_UVAL,
		//dst, dst-arg, uval
		MATCHACTION_ARG_FVAL,
		//dst, dst-arg, favl
		
		MATCHACTION_ARG_MEM,
		MATCHACTION_ARG_STACK,
		MATCHACTION_ARG_REG
		//dst, dst-arg, ref
	};
	struct MatchActionSelector{
		HId createExprIndex;
		HId foundExprIndex;
		HId argIndex;
	};
	
	struct MatchAction{
		MatchActionType actionType = MATCHACTION_INVALID;
		MatchActionSelector src = {0,0,0};
		MatchActionSelector dst = {0,0,0};
		
		union{
			struct{
				SSAExprType type;
				SSAOpType opType;
				SSAFlagType flagType;
			}types;
			uint32_t inheritInstrFlags;
			uint32_t inheritArgFlags;
			SSAType exprType;
			HId builtinId;
			uint32_t size;
			uint64_t uval;
			int64_t sval;
			double fval;
			Reference ref;
		};
		
		void doAction(SSARepresentation* rep, MatchContext* context);
		
	};
	inline MatchAction createInheritInstrAction(MatchActionSelector src, MatchActionSelector dst, uint32_t inheritInstrFlags){
		MatchAction action;
		action.actionType = MATCHACTION_INHERIT_INSTR;
		action.src = src;
		action.dst = dst;
		action.inheritInstrFlags = inheritInstrFlags;
		return action;
	};
	inline MatchAction createInheritArgAction(MatchActionSelector src, MatchActionSelector dst, uint32_t inheritArgFlags){
		MatchAction action;
		action.actionType = MATCHACTION_INHERIT_ARG;
		action.src = src;
		action.dst = dst;
		action.inheritArgFlags = inheritArgFlags;
		return action;
	};
	inline MatchAction createInheritArgsAction(MatchActionSelector src, MatchActionSelector dst, uint32_t count){
		MatchAction action;
		action.actionType = MATCHACTION_INHERIT_ARGS;
		action.src = src;
		action.dst = dst;
		action.size = count;
		return action;
	};
	inline MatchAction createInsertInstrAction(MatchActionSelector dst){
		MatchAction action;
		action.actionType = MATCHACTION_INSTR_INSERT_AS_ARG;
		action.dst = dst;
		return action;
	};
	inline MatchAction createInstrTypeAction(MatchActionSelector dst, SSAExprType type, SSAOpType opType = H_OP_INVALID, SSAFlagType flagType = SSA_FLAG_UNKNOWN){
		MatchAction action;
		action.actionType = MATCHACTION_INSTR_TYPE;
		action.dst = dst;
		action.types.type = type;
		action.types.opType = opType;
		action.types.flagType = flagType;
		return action;
	};
	inline MatchAction createInstrSizeAction(MatchActionSelector dst, uint32_t size){
		MatchAction action;
		action.actionType = MATCHACTION_INSTR_SIZE;
		action.size = size;
		return action;
	};
	inline MatchAction createInstrExprTypeAction(MatchActionSelector dst, SSAType exprType){
		MatchAction action;
		action.actionType = MATCHACTION_INSTR_EXPRTYPE;
		action.dst = dst;
		action.exprType = exprType;
		return action;
	};
	inline MatchAction createInstrBuiltinTypeAction(MatchActionSelector dst, uint32_t builtinId){
		MatchAction action;
		action.actionType = MATCHACTION_INSTR_BUILTIN;
		action.dst = dst;
		action.builtinId = builtinId;
		return action;
	};
	inline MatchAction createInstrValueAction(MatchActionSelector dst, uint64_t uval){
		MatchAction action;
		action.actionType = MATCHACTION_ARG_UVAL;
		action.dst = dst;
		action.uval = uval;
		return action;
	};
	inline MatchAction createInstrValueAction(MatchActionSelector dst, int64_t sval){
		MatchAction action;
		action.actionType = MATCHACTION_ARG_SVAL;
		action.dst = dst;
		action.sval = sval;
		return action;
	};
	inline MatchAction createInstrValueAction(MatchActionSelector dst, double fval){
		MatchAction action;
		action.actionType = MATCHACTION_ARG_FVAL;
		action.dst = dst;
		action.fval = fval;
		return action;
	};
	inline MatchAction createInstrMemLocAction(MatchActionSelector dst, Reference ref){
		MatchAction action;
		action.actionType = MATCHACTION_ARG_MEM;
		action.dst = dst;
		action.ref = ref;
		return action;
	};
	inline MatchAction createInstrStackLocAction(MatchActionSelector dst, Reference ref){
		MatchAction action;
		action.actionType = MATCHACTION_ARG_STACK;
		action.dst = dst;
		action.ref = ref;
		return action;
	};
	inline MatchAction createInstrRegLocAction(MatchActionSelector dst, Reference ref){
		MatchAction action;
		action.actionType = MATCHACTION_ARG_REG;
		action.dst = dst;
		action.ref = ref;
		return action;
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
		//
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
