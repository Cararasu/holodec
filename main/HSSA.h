
#ifndef HSSA_H
#define HSSA_H

#include "HId.h"
#include "HStack.h"
#include "HRegister.h"
#include "HArgument.h"
#include "HGeneral.h"

#define HSSA_LOCAL_USEID_MAX (4)

namespace holodec {

	class HArchitecture;
	
#define HSSA_EXPR_CONTROL_FLOW	(0x1000)
	
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
		HSSA_EXPR_UPDATEPART= 0x19,
		HSSA_EXPR_APPEND	= 0x1A,
		HSSA_EXPR_CAST		= 0x1B,
		
		HSSA_EXPR_INPUT		= 0x21,
		HSSA_EXPR_OUTPUT	= 0x22,
		
		HSSA_EXPR_CALL		= HSSA_EXPR_CONTROL_FLOW | 0x23,
		HSSA_EXPR_RETURN	= HSSA_EXPR_CONTROL_FLOW | 0x24,
		HSSA_EXPR_SYSCALL	= HSSA_EXPR_CONTROL_FLOW | 0x25,
		HSSA_EXPR_TRAP		= HSSA_EXPR_CONTROL_FLOW | 0x26,

		HSSA_EXPR_PHI		= 0x31,
		HSSA_EXPR_ASSIGN	= 0x32,

		HSSA_EXPR_JMP		= HSSA_EXPR_CONTROL_FLOW | 0x41,
		HSSA_EXPR_CJMP		= HSSA_EXPR_CONTROL_FLOW | 0x42,
		HSSA_EXPR_MULTIBR	= HSSA_EXPR_CONTROL_FLOW | 0x43,

		HSSA_EXPR_PUSH		= 0x51,
		HSSA_EXPR_POP		= 0x52,
		HSSA_EXPR_STORE		= 0x53,
		HSSA_EXPR_LOAD		= 0x54,

	};
	enum HSSAOpType {
		HSSA_OP_INVALID = 0,
		HSSA_OP_ADD,
		HSSA_OP_SUB,
		HSSA_OP_MUL,
		HSSA_OP_DIV,
		HSSA_OP_MOD,

		HSSA_OP_AND,
		HSSA_OP_OR,
		HSSA_OP_XOR,
		HSSA_OP_NOT,

		HSSA_OP_E,
		HSSA_OP_NE,
		HSSA_OP_L,
		HSSA_OP_LE,
		HSSA_OP_G,
		HSSA_OP_GE,

		HSSA_OP_BAND,
		HSSA_OP_BOR,
		HSSA_OP_BXOR,
		HSSA_OP_BNOT,

		HSSA_OP_SHR,
		HSSA_OP_SHL,
		HSSA_OP_SAR,
		HSSA_OP_SAL,
		HSSA_OP_ROR,
		HSSA_OP_ROL,
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
	struct HSSAExpression {
		HId id = 0;
		HSSAExprType type = HSSA_EXPR_INVALID;
		uint64_t size = 0;
		HSSAType exprtype = HSSA_TYPE_UNKNOWN;
		union { //64 bit
			HSSAFlagType flagType;
			HId index;
			HSSAOpType opType;
			HId builtinId;
			HId instrId;
		};
		HId regId = 0;
		HArgStck stackId = {0,0};
		HId memId = 0;
		uint64_t instrAddr = 0;
		
		//HLocalBackedList<HArgument, HSSA_LOCAL_USEID_MAX> subExpressions;
		HList<HArgument> subExpressions;

		bool operator!() {
			return type == HSSA_EXPR_INVALID;
		}
		operator bool() {
			return type != HSSA_EXPR_INVALID;
		}
		void print(HArchitecture* arch, int indent = 0);
	};
	inline bool operator== (HSSAExpression& lhs, HSSAExpression& rhs) {
		if (lhs.type == rhs.type && lhs.size == rhs.size && lhs.exprtype == rhs.exprtype && lhs.regId == rhs.regId && lhs.stackId == rhs.stackId) {
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
				return lhs.index == rhs.index;
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

		HSSABB() {}
		HSSABB (HId fallthroughId, uint64_t startaddr, uint64_t endaddr, HList<HId> exprIds) :id(0),fallthroughId(fallthroughId),startaddr(startaddr),endaddr(endaddr),exprIds(exprIds){}
		~HSSABB() = default;


		HId getInputSSA (HRegister* reg);
	};


	struct HSSARepresentation {
		HIdList<HSSABB> bbs;
		HIdList<HSSAExpression> expressions;

		void clear(){
			bbs.clear();
			expressions.clear();
		}

		void replaceNode(HId origId, HArgument target){
			for(HSSAExpression& expr : expressions){
				for (HArgument& arg : expr.subExpressions) {
					if(arg.id == origId){
						arg.id = target;
					}
				}
			}
		}
		void replaceNodes(HList<std::pair<HId,HArgument>>* replacements){
			
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
				for (HArgument& arg : expr.subExpressions) {
					for(std::pair<HId,HArgument>& rep : *replacements){
						if(arg.id == rep.first){
							arg = rep.second;
						}
					}
				}
			}
			
			for(HSSABB& bb : bbs){
				for(auto it = bb.exprIds.begin(); it != bb.exprIds.end();){
					HId id = *it;
					bool erased = false;
					for(std::pair<HId,HArgument>& rep : *replacements){
						if(rep.first == id){
							bb.exprIds.erase(it);
							erased = true;
							break;
						}
					}
					if(erased)
						continue;
					it++;
				}
			}
			for(auto it = expressions.begin(); it != expressions.end();){
				HSSAExpression& expr = *it;
				bool erased = false;
				for(std::pair<HId,HArgument>& rep : *replacements){
					if(expr.id == rep.first){
						expressions.erase(it);
						erased = true;
						break;
					}
				}
				if(erased)
					continue;
				it++;
			}
		}

		void print (HArchitecture* arch, int indent = 0);
	};
}

#endif //HSSA_H
