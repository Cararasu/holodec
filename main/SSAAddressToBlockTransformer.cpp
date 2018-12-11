
#include "SSAAddressToBlockTransformer.h"
#include "SSA.h"
#include "Function.h"
#include "Architecture.h"


namespace holodec {

	bool SSAAddressToBlockTransformer::resolveDstTarget(SSABB& block, SSAExpression& expr, SSAArgument& arg) {
		SSAExpression* dstExpr = find_baseexpr(&function->ssaRep, arg);
		if (dstExpr->isConst(SSAType::eUInt)) {
			for (SSABB& bb : function->ssaRep.bbs) {
				if (bb.startaddr == dstExpr->uval) {
					arg = SSAArgument::createBlock(bb.id);
					block.outBlocks.insert(bb.id);
					bb.inBlocks.insert(block.id);
					return true;
				}
			}
		}
		else {
			if (arg.type != SSAArgType::eBlock) {
				SSAExpression& loadExpr = function->ssaRep.expressions[arg.ssaId];
				if (loadExpr.type == SSAExprType::eLoad) {
					uint64_t baseaddr;
					if (loadExpr.subExpressions[0].ssaId && function->ssaRep.calcConstValue(loadExpr.subExpressions[0], &baseaddr)) {
						if (arch->bytebase < sizeof(uint64_t))
							baseaddr %= ((uint64_t)1 << (arch->bytebase * arch->bitbase));

						Symbol* sym = binary->findSymbol(baseaddr, &SymbolType::symdynfunc);
						if (sym) {
							sym->print();
						}
					}
				}
			}
			return true;
		}
		return false;
	}
	bool SSAAddressToBlockTransformer::doTransformation(Binary* binary, Function* function){

		this->binary = binary;
		this->function = function;
		bool applied = false;

		function->print(binary->arch);
		fflush(stdout);

		for (SSABB& block : function->ssaRep.bbs) {
			if (block.exprIds.size() && function->ssaRep.expressions[block.exprIds.back()].type == SSAExprType::eReturn)//if last statement is return then we do nothing
				continue;
			if (function->ssaRep.expressions[block.exprIds.back()].type != SSAExprType::eBranch && function->ssaRep.expressions[block.exprIds.back()].type != SSAExprType::eReturn) {
				for (SSABB& bb : function->ssaRep.bbs) {
					if (bb.startaddr == block.endaddr) {
						SSAExpression branchExpr(SSAExprType::eBranch, arch->bitbase * arch->bytebase, SSAType::ePc);
						branchExpr.subExpressions = { SSAArgument::createBlock(bb.id) };
						function->ssaRep.addAtEnd(&branchExpr, &block);
						block.outBlocks.insert(bb.id);
						bb.inBlocks.insert(block.id);
						break;
					}
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
