
#ifndef HSSA_H
#define HSSA_H


#include "HStack.h"
#include "HRegister.h"
#include "HArgument.h"
#include "HGeneral.h"
#include "HIdList.h"

#define HSSA_LOCAL_USEID_MAX (4)

namespace holodec {

	class HArchitecture;
	
#define HSSA_EXPR_CONTROL_FLOW		(0x1000)
#define HSSA_EXPR_TRANSIENT_NODE	(0x2000)//TODO rename as this is a bad name
	
	enum HSSAExprType {
		HSSA_EXPR_INVALID	= 0x0,
		
		HSSA_EXPR_LABEL		= 0x10,
		HSSA_EXPR_UNDEF		= 0x11,
		HSSA_EXPR_NOP		= 0x12,
		
		HSSA_EXPR_OP		= 0x13,
		HSSA_EXPR_MEM		= 0x14,
		HSSA_EXPR_FLAG		= 0x15,
		HSSA_EXPR_BUILTIN	= 0x16,
		HSSA_EXPR_EXTEND	= 0x17,
		HSSA_EXPR_SPLIT		= 0x18,
		HSSA_EXPR_UPDATEPART= HSSA_EXPR_TRANSIENT_NODE | 0x19,
		HSSA_EXPR_APPEND	= 0x1A,
		HSSA_EXPR_CAST		= 0x1B,
		
		HSSA_EXPR_INPUT		= 0x21,
		HSSA_EXPR_OUTPUT	= 0x22,
		
		HSSA_EXPR_CALL		= HSSA_EXPR_CONTROL_FLOW | 0x23,
		HSSA_EXPR_RETURN	= HSSA_EXPR_CONTROL_FLOW | 0x24,
		HSSA_EXPR_SYSCALL	= HSSA_EXPR_CONTROL_FLOW | 0x25,
		HSSA_EXPR_TRAP		= HSSA_EXPR_CONTROL_FLOW | 0x26,

		HSSA_EXPR_PHI		= HSSA_EXPR_TRANSIENT_NODE | 0x31,
		HSSA_EXPR_ASSIGN	= HSSA_EXPR_TRANSIENT_NODE | 0x32,

		HSSA_EXPR_JMP		= HSSA_EXPR_CONTROL_FLOW | 0x41,
		HSSA_EXPR_CJMP		= HSSA_EXPR_CONTROL_FLOW | 0x42,
		HSSA_EXPR_MULTIBR	= HSSA_EXPR_CONTROL_FLOW | 0x43,

		HSSA_EXPR_PUSH		= 0x51,
		HSSA_EXPR_POP		= 0x52,
		HSSA_EXPR_STORE		= 0x53,
		HSSA_EXPR_LOAD		= 0x54,

	};
	enum HSSAOpType {
		H_OP_INVALID = 0,
		H_OP_ADD,
		H_OP_SUB,
		H_OP_MUL,
		H_OP_DIV,
		H_OP_MOD,

		H_OP_AND,
		H_OP_OR,
		H_OP_XOR,
		H_OP_NOT,

		H_OP_EQ,
		H_OP_NE,
		H_OP_L,
		H_OP_LE,
		H_OP_G,
		H_OP_GE,

		H_OP_BAND,
		H_OP_BOR,
		H_OP_BXOR,
		H_OP_BNOT,

		H_OP_SHR,
		H_OP_SHL,
		H_OP_SAR,
		H_OP_SAL,
		H_OP_ROR,
		H_OP_ROL,
	};
	enum HSSAType {
		HSSA_TYPE_UNKNOWN = 0,
		HSSA_TYPE_INT,
		HSSA_TYPE_UINT,
		HSSA_TYPE_FLOAT,
		HSSA_TYPE_PC,
		HSSA_TYPE_MEM,
	};
	enum HSSAFlagType {
		HSSA_FLAG_C,
		HSSA_FLAG_A,
		HSSA_FLAG_P,
		HSSA_FLAG_O,
		HSSA_FLAG_U,
		HSSA_FLAG_Z,
		HSSA_FLAG_S,
	};
	enum HSSAExprLocation{
		HSSA_LOCATION_NONE,
		HSSA_LOCATION_REG,
		HSSA_LOCATION_STACK,
		HSSA_LOCATION_MEM,
	};
	struct HSSAExpression {
		HId id = 0;
		HSSAExprType type = HSSA_EXPR_INVALID;
		uint64_t size = 0;
		HSSAType exprtype = HSSA_TYPE_UNKNOWN;
		union { //64 bit
			HSSAFlagType flagType;
			HSSAOpType opType;
			HId builtinId;
			HId instrId;
		};
		HSSAExprLocation location = HSSA_LOCATION_NONE;
		HReference locref = {0,0};
		uint64_t instrAddr = 0;
		
		//HLocalBackedList<HSSAArgument, HSSA_LOCAL_USEID_MAX> subExpressions;
		HList<HSSAArgument> subExpressions;

		bool operator!() {
			return type == HSSA_EXPR_INVALID;
		}
		operator bool() {
			return type != HSSA_EXPR_INVALID;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	inline bool operator== (HSSAExpression& lhs, HSSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype && lhs.location == rhs.location && lhs.locref.refId == rhs.locref.refId && lhs.locref.index == rhs.locref.index) {
			if (lhs.subExpressions.size() == rhs.subExpressions.size()) {
				for (size_t i = 0; i < lhs.subExpressions.size(); i++) {
					if (lhs.subExpressions[i] != rhs.subExpressions[i])
						return false;
				}
			}
			switch (rhs.type) {
			case HSSA_EXPR_FLAG:
				return lhs.flagType == rhs.flagType;
			case HSSA_EXPR_OP:
				return lhs.opType == rhs.opType;
			case HSSA_EXPR_BUILTIN:
				return lhs.builtinId == rhs.builtinId;
			default:
				return true;
			}
		}
		return false;
	}
	
	struct HSSABB {
		HId id;
		HId fallthroughId = 0;
		uint64_t startaddr = (uint64_t)-1;
		uint64_t endaddr = 0;
		HList<HId> exprIds;
		HSet<HId> inBlocks;
		HSet<HId> outBlocks;

		HSSABB() {}
		HSSABB (HId fallthroughId, uint64_t startaddr, uint64_t endaddr, HList<HId> exprIds, HSet<HId> inBlocks, HSet<HId> outBlocks) :
			id(0),fallthroughId(fallthroughId),startaddr(startaddr),endaddr(endaddr),exprIds(exprIds),inBlocks(inBlocks),outBlocks(outBlocks){}
		~HSSABB() = default;


		HId getInputSSA (HRegister* reg);
	};


	struct HSSARepresentation {
		HIdList<HSSABB> bbs;
		HSparseIdList<HSSAExpression> expressions;

		void clear(){
			bbs.clear();
			expressions.clear();
		}

		void replaceNodes(HMap<HId,HSSAArgument>* replacements){
			
			bool replaced = false;
			do{
				replaced = false;
				for(auto it = replacements->begin(); it != replacements->end();++it){
					if((*it).first == (*it).second.id)//to prevent unlimited loops in circualr dependencies
						continue;
					auto innerIt = it;
					for(++innerIt; innerIt != replacements->end(); ++innerIt){
						if((*it).first == (*innerIt).second.id){
							(*innerIt).second = (*it).second;
							replaced = true;
						}else if((*innerIt).first == (*it).second.id){
							(*it).second = (*innerIt).second;
							replaced = true;
						}
					}
				}
			}while(replaced);
			
			for(HSSAExpression& expr : expressions){
				for (HSSAArgument& arg : expr.subExpressions) {
					auto repIt = replacements->find(arg.id);
					if(repIt != replacements->end()){
						arg = repIt->second;
					}
				}
			}
			
			for(HSSABB& bb : bbs){
				for(auto it = bb.exprIds.begin(); it != bb.exprIds.end();){
					if(replacements->find(*it) != replacements->end()){
						bb.exprIds.erase(it);
						continue;
					}
					it++;
				}
			}
			for(auto it = expressions.begin(); it != expressions.end();){
				if(replacements->find(it->id) != replacements->end()){
					expressions.erase(it);
					continue;
				}
				it++;
			}
		}
		void removeNodes(HSet<HId>* ids){
			for(auto it = expressions.begin(); it != expressions.end();){
				if(ids->find(it->id) != ids->end()){
					expressions.erase(it);
					continue;
				}
				for(HSSAArgument& arg : it->subExpressions){
					if(arg.id && ids->find(it->id) != ids->end())
						arg = HSSAArgument::create(HSSA_ARGTYPE_UNKN);
				}
				++it;
			}
			for(HSSABB& bb : bbs){
				for(auto it = bb.exprIds.begin(); it != bb.exprIds.end();){
					if(ids->find(*it) != ids->end()){
						bb.exprIds.erase(it);
						continue;
					}
					++it;
				}
			}
		}
		
		void compress(){
			
			std::map<HId, HId> replacements;
			
			expressions.shrink([&replacements](HId oldId, HId newId){replacements[oldId] = newId;});
			
			if(!replacements.empty()){
				for(HSSAExpression& expr : expressions){
					for(HSSAArgument& arg : expr.subExpressions){
						auto it = replacements.find(arg.id);
						if(it != replacements.end()){
							arg.id = it->second;
						}
					}
				}
				for(HSSABB& bb : bbs){
					for(HId& id : bb.exprIds){
						auto it = replacements.find(id);
						if(it != replacements.end()){
							id = it->second;
						}
					}
				}
			}
			
		}


		void print (HArchitecture* arch, int indent = 0);
	};
}

#endif //HSSA_H
