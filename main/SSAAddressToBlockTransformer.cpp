
#include "SSAAddressToBlockTransformer.h"
#include "SSA.h"
#include "Function.h"
#include "Architecture.h"


namespace holodec {

	bool SSAAddressToBlockTransformer::resolveDstTarget(SSABB& block, SSAExpression& expr, SSAArgument& arg) {
		if (arg.type == SSAArgType::eUInt) {
			for (SSABB& bb : function->ssaRep.bbs) {
				if (bb.startaddr == arg.uval) {
					arg = SSAArgument::createBlock(bb.id);
					block.outBlocks.insert(bb.id);
					bb.inBlocks.insert(block.id);
					return true;
				}
			}
		}
		else {
			if (arg.type == SSAArgType::eOther && arg.location != SSALocation::eBlock) {
				SSAExpression& loadExpr = function->ssaRep.expressions[arg.ssaId];
				if (loadExpr.type == SSAExprType::eLoad) {
					uint64_t baseaddr;
					if (function->ssaRep.calcConstValue(loadExpr.subExpressions[0], &baseaddr)) {
						if (arch->bytebase < sizeof(uint64_t))
							baseaddr %= ((uint64_t)1 << (arch->bytebase * arch->bitbase));

						Symbol* sym = binary->findSymbol(baseaddr, &SymbolType::symdynfunc);
						if (sym) {
							sym->print();
						}
					}
				}
			}
			for (Register& reg : arch->registers) {
				if (!reg.id || reg.directParentRef)
					continue;
				expr.subExpressions.push_back(SSAArgument::createReg(&reg, 0));
			}
			return true;
		}
		return false;
	}
	bool SSAAddressToBlockTransformer::doTransformation(Binary* binary, Function* function){

		this->binary = binary;
		this->function = function;
		bool applied = false;

		for (SSABB& block : function->ssaRep.bbs) {
			if (block.exprIds.size() && function->ssaRep.expressions[block.exprIds.back()].type == SSAExprType::eReturn)//if last statement is return then we do nothing
				continue;
			if (!block.fallthroughId) {
				if (function->ssaRep.expressions[block.exprIds.back()].type != SSAExprType::eBranch && function->ssaRep.expressions[block.exprIds.back()].type != SSAExprType::eReturn) {
					for (SSABB& bb : function->ssaRep.bbs) {
						if (bb.startaddr == block.endaddr) {
							block.fallthroughId = bb.id;
							block.outBlocks.insert(bb.id);
							bb.inBlocks.insert(block.id);
							break;
						}
					}
				}
				else {
					block.fallthroughId = 0;
				}
			}

			for (HId& id : block.exprIds) {
				SSAExpression& expression = function->ssaRep.expressions[id];
				if (expression.type == SSAExprType::eBranch) {
					for (size_t i = 0; i < expression.subExpressions.size(); i += 2)
						applied |= resolveDstTarget(block, expression, expression.subExpressions[i]);
				}
			}
		}

		return applied;
	}
}
