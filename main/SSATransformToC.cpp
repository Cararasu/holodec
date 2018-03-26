#include "SSATransformToC.h"


namespace holodec{

	//gather outputs
	//mark every nodes outwards of outputs
	//if there exists a node that has the same number of marks as 
	//

	bool SSATransformToC::analyzeLoop(HId bbId, ControlStruct* loopStruct) {
		HMap<HId, bool> visitedBlocks;
		SSABB* basicBlock = &function->ssaRep.bbs[bbId];
		visitedBlocks.insert(std::make_pair(bbId, true));
		bool isLoop = false;
		for (HId id : basicBlock->outBlocks) {
			isLoop |= analyzeLoop(id, visitedBlocks, loopStruct);
		}
		loopStruct->contained_blocks.insert(bbId);

		for (HId id : basicBlock->outBlocks) {
			auto it = visitedBlocks.find(id);
			if (it != visitedBlocks.end() && !it->second) {
				loopStruct->exit_blocks.insert(id).first->count++;
			}
			printf("Wups %d -> %d, %d\n", bbId, id, it->second);
		}
		return isLoop;
	}
	bool SSATransformToC::analyzeLoop(HId bbId, HMap<HId, bool>& visitedBlocks, ControlStruct* loopStruct) {
		printf("Loop %d\n", bbId);
		auto it = visitedBlocks.find(bbId);
		if (it != visitedBlocks.end()) {
			printf("Visited %d\n", bbId);
			return it->second;
		}
		it = visitedBlocks.insert(std::make_pair(bbId, false)).first;

		SSABB* basicBlock = &function->ssaRep.bbs[bbId];
		bool reachesHead = false;
		for (HId id : basicBlock->outBlocks) {
			reachesHead |= analyzeLoop(id, visitedBlocks, loopStruct);
			it->second = reachesHead;
		}
		if (reachesHead) {
			for (HId id : basicBlock->outBlocks) {
				auto it = visitedBlocks.find(id);
				if (it != visitedBlocks.end() && !it->second) {
					loopStruct->exit_blocks.insert(id).first->count++;
				}
				printf("Wups %d -> %d, %d\n", bbId, id, it->second);
			}
		}
		if (reachesHead)
			loopStruct->contained_blocks.insert(bbId);
		return reachesHead;
	}
	void SSATransformToC::analyzeOutputBranch(HId bbId, HSet<std::pair<HId, HId>>& forwardEdges) {

		SSABB* basicBlock = &function->ssaRep.bbs[bbId];
		for (auto it = basicBlock->outBlocks.begin(); it != basicBlock->outBlocks.end(); ++it) {
			auto engeIt = forwardEdges.find(std::make_pair(bbId, *it));
			if (engeIt == forwardEdges.end()) {
				forwardEdges.insert(std::make_pair(bbId, *it));
			}
			else {
				return;
			}
			analyzeOutputBranch(*it, forwardEdges);
		}
	}
	void SSATransformToC::analyzeStructure(ControlStruct& controlStruct, HId start_block_id) {

		for (ControlStruct& child : controlStruct.child_struct) {
			if (child.contained_blocks.find(start_block_id) != child.contained_blocks.end()) {
				child.input_blocks.insert(start_block_id).first->count++;
				return;
			}
		}

		SSABB* basicBlock = &function->ssaRep.bbs[start_block_id];
		ControlStruct* createdStruct = nullptr;
		if (basicBlock->inBlocks.size() > 1) {//Loop - Check
			createdStruct = new ControlStruct(ControlStructType::LOOP);
			createdStruct->parent_struct = &controlStruct;
			createdStruct->input_blocks.insert(basicBlock->id).first->count++;
			if(!analyzeLoop(start_block_id, createdStruct)){
				delete createdStruct;
				createdStruct = nullptr;
			}
		}
		else if (basicBlock->outBlocks.size() > 1) {//Branch - Check
			createdStruct = new ControlStruct(ControlStructType::BRANCH);
			createdStruct->parent_struct = &controlStruct;
			createdStruct->input_blocks.insert(basicBlock->id).first->count++;
			createdStruct->contained_blocks.insert(basicBlock->id);
			for (auto it = basicBlock->outBlocks.begin(); it != basicBlock->outBlocks.end(); ++it) {
				createdStruct->exit_blocks.insert(*it).first->count++;
			}

			HSet<std::pair<HId, HId>> forwardEdges, backwardsEdges;

			for (auto it = basicBlock->outBlocks.begin(); it != basicBlock->outBlocks.end(); ++it) {
				analyzeOutputBranch(*it, forwardEdges);
			}
			for (std::pair<HId, HId> entry : forwardEdges) {
				printf("Edge Forward %d -> %d\n", entry.first, entry.second);
			}
			for (std::pair<HId, HId> entry : backwardsEdges) {
				printf("Edge Backwards %d -> %d\n", entry.first, entry.second);
			}
		}
		else if (basicBlock->outBlocks.size() == 1) {
			createdStruct = new ControlStruct(ControlStructType::SEQUENCE);
			createdStruct->parent_struct = &controlStruct;
			createdStruct->input_blocks.insert(basicBlock->id).first->count++;
			bool tail = false;
			do {
				createdStruct->contained_blocks.insert(basicBlock->id);
				basicBlock = &function->ssaRep.bbs[basicBlock->outBlocks[0]];
			} while (basicBlock->outBlocks.size() == 1 && basicBlock->inBlocks.size() == 1);
			if(!tail)
				createdStruct->exit_blocks.insert(basicBlock->id).first->count++;
		}
		if (createdStruct) {
			controlStruct.child_struct.push_back(*createdStruct);
			for (auto it = createdStruct->exit_blocks.begin(); it != createdStruct->exit_blocks.end(); ++it) {
				IOBlock exit_id = *it;
				SSABB* block = &function->ssaRep.bbs[exit_id.blockId];
				if (block->inBlocks.size() == 1 && block->outBlocks.size() == 1) {
					analyzeStructure(*createdStruct, exit_id.blockId);
					it = createdStruct->exit_blocks.erase(it);
					createdStruct->exit_blocks.insert(block->outBlocks[0]).first->count++;
				}
				else {
					analyzeStructure(controlStruct, exit_id.blockId);
					printf("Tail: %d\n", exit_id);
				}
			}
		}
		
		fflush(stdout);
	}
	bool SSATransformToC::shouldResolve(SSAExpression& expr) {
		if (resolveIds.find(expr.id) != resolveIds.end()) {
			return true;
		}
		if (expr.refs.size() > 1) {
			return true;
		}
		if (EXPR_HAS_SIDEEFFECT(expr.type)) {
			return true;
		}
		return false;
	}


	void SSATransformToC::printBasicBlock(SSABB& bb) {
		if(resolveBBs.find(bb.id) != resolveBBs.end())
			printf("Label L%d:\n", bb.id);
		for (HId id : bb.exprIds) {
			SSAExpression& expr = function->ssaRep.expressions[id];
			if (shouldResolve(expr))
				printExpression(expr);
		}

		if(bb.fallthroughId && bb.fallthroughId != bb.id + 1)
			printf("goto L%d\n", bb.fallthroughId);
	}
	void SSATransformToC::resolveArgs(SSAExpression& expr, const char* delimiter) {
		printf("(");
		for (size_t i = 0; i < expr.subExpressions.size(); i++) {
			SSAArgument& arg = expr.subExpressions[i];
			if (arg.type == SSAArgType::eOther)
				continue;
			resolveArg(arg);
			if(i + 1 != expr.subExpressions.size())
				printf("%s", delimiter);
		}
		printf(")");
	}
	UnifiedExprs* SSATransformToC::getUnifiedExpr(HId uId) {
		for (UnifiedExprs& exprs : unifiedExprs) {
			if (exprs.occuringIds.find(uId) != exprs.occuringIds.end()) {
				return &exprs;
			}
		}
		return nullptr;
	}
	void SSATransformToC::resolveArgWithoutOffset(SSAArgument& arg) {
		switch (arg.type) {
		case SSAArgType::eUndef:
			printf("undef");
			break;
		case SSAArgType::eSInt:
			printf("%d", arg.sval);
			break;
		case SSAArgType::eUInt:
			printf("0x%x", arg.uval);
			break;
		case SSAArgType::eFloat:
			printf("%f", arg.fval);
			break;
		case SSAArgType::eId: {
			SSAExpression& subExpr = function->ssaRep.expressions[arg.ssaId];
			bool nonZeroOffset = (arg.offset != 0), nonFullSize = (arg.offset + arg.size != subExpr.size);
			if (nonFullSize) {
				printf("(");
				if (subExpr.exprtype == SSAType::eFloat)
					printf("(float_%d) ", arg.size);
				else if (subExpr.exprtype == SSAType::eUInt)
					printf("(uint%d_t) ", arg.size);
				else if (subExpr.exprtype == SSAType::eInt)
					printf("(int%d_t) ", arg.size);
			}
			if (nonZeroOffset)
				printf("(");

			if (UnifiedExprs* uExprs = getUnifiedExpr(subExpr.uniqueId)) {
				printf("var%d", uExprs->id);
			}
			else if (resolveIds.find(subExpr.id) != resolveIds.end()) {
				printf("tmp%d", subExpr.id);
			}
			else {
				resolveExpression(subExpr);
			}
			if (nonZeroOffset)
				printf(" >> %d)", arg.offset);
			if (nonFullSize)
				printf(")");
		}break;
		case SSAArgType::eOther:
			break;
		}
	}
	void SSATransformToC::resolveArg(SSAArgument& arg) {
		resolveArgWithoutOffset(arg);
		if(arg.valueoffset > 0){
			printf(" + %d ", arg.valueoffset);
		}else if(arg.valueoffset < 0){
			printf(" - %d ", arg.valueoffset * -1);
		}
	}
	void SSATransformToC::resolveMemArg(SSAArgument& arg, uint32_t size) {
		uint32_t bytesize = arch->bitToByte(size);
		if (bytesize == 1) {
			resolveArgWithoutOffset(arg);
			printf("[%d]", arg.valueoffset);
		}
		else {
			printf("*((uint%d_t *)", size);
			resolveArg(arg);
			printf(")");
		}
	}
	void SSATransformToC::resolveExpression(SSAExpression& expr) {

		if (expr.type != SSAExprType::eInput && expr.type != SSAExprType::eCall)
			printf("(");
		switch (expr.type) {
		case SSAExprType::eInvalid:
			break;
		case SSAExprType::eLabel:
			break;
		case SSAExprType::eUndef:
			printf("undef ");
			break;
		case SSAExprType::eNop:
			break;
		case SSAExprType::eOp: {
			for (size_t i = 0; i < expr.subExpressions.size(); ++i) {
				SSAArgument& arg = expr.subExpressions[i];
				resolveArg(arg);
				if (i + 1 != expr.subExpressions.size()) {
					switch (expr.opType) {
					case SSAOpType::eMul:
						printf(" * ");
						break;
					case SSAOpType::eDiv:
						printf(" / ");
						break;
					case SSAOpType::eSub:
						printf(" - ");
						break;
					case SSAOpType::eAdd:
						printf(" + ");
						break;
					case SSAOpType::eAnd:
						printf(" && ");
						break;
					case SSAOpType::eOr:
						printf(" || ");
						break;
					case SSAOpType::eEq:
						printf(" == ");
						break;
					case SSAOpType::eNe:
						printf(" != ");
						break;
					case SSAOpType::eLe:
						printf(" <= ");
						break;
					case SSAOpType::eLower:
						printf(" < ");
						break;
					case SSAOpType::eGe:
						printf(" >= ");
						break;
					case SSAOpType::eGreater:
						printf(" > ");
						break;
					default:
						printf(" op ");
					}
				}
			}
		}break;
		case SSAExprType::eLoadAddr:
			printf("[");
			resolveArg(expr.subExpressions[1]);
			printf("+");
			resolveArg(expr.subExpressions[2]);
			printf("*");
			resolveArg(expr.subExpressions[3]);
			printf("+");
			resolveArg(expr.subExpressions[4]);
			printf("]");
			break;
		case SSAExprType::eFlag:
			printf("Flag-");
			switch (expr.flagType) {
			case SSAFlagType::eC:
				printf("Carry");
				break;
			case SSAFlagType::eO:
				printf("Overflow");
				break;
			case SSAFlagType::eU:
				printf("Underflow");
				break;
			}
			printf("(");
			resolveArg(expr.subExpressions[0]);
			printf(")");
			break;
		case SSAExprType::eBuiltin:{
			printf("%s ", arch->getBuiltin(expr.builtinId)->name.cstr());
			resolveArgs(expr);
		}break;
		case SSAExprType::eExtend: {
			if (expr.exprtype == SSAType::eFloat)
				printf("(float_%d)", expr.size);
			else if (expr.exprtype == SSAType::eInt)
				printf("(int%d_t)", expr.size);
			else if (expr.exprtype == SSAType::eUInt)
				printf("(uint%d_t)", expr.size);
			else
				printf("extend%d", expr.size);
			resolveArgs(expr);
		}break;
		case SSAExprType::eAppend: {
			printf("(");
			uint32_t offset = 0;
			for (size_t i = 0; i < expr.subExpressions.size(); i++) {
				SSAArgument& arg = expr.subExpressions[i];
				resolveArg(arg);
				if(offset)
					printf(" << %d", offset);
				offset += arg.size;
				if (i + 1 != expr.subExpressions.size())
					printf(" | ");
			}
			printf(")");
		}break;
		case SSAExprType::eCast: {
			if (expr.exprtype == SSAType::eFloat)
				printf("F");
			else if (expr.exprtype == SSAType::eInt)
				printf("S");
			else if (expr.exprtype == SSAType::eUInt)
				printf("U");
			printf("Cast%d ", expr.size);
			resolveArgs(expr);
		}break;

		case SSAExprType::eInput:
			for (CArgument& arg : arguments) {
				if (arg.ssaId == expr.id) {
					printf("arg%d", arg.id);
				}
			}
			break;
		case SSAExprType::eOutput:
			break;

		case SSAExprType::eCall: {
			for (HId id : expr.directRefs) {
				SSAExpression& refExpr = function->ssaRep.expressions[id];
				if (refExpr.type == SSAExprType::eOutput && refExpr.location == SSALocation::eReg) {
					printf("tmp%d <- %s, ", refExpr.id, arch->getRegister(refExpr.locref.refId)->name.cstr());
				}
			}
			printf("Call ");
			resolveArg(expr.subExpressions[0]);
			printf("(");
			for (size_t i = 0; i < expr.subExpressions.size(); i++) {
				SSAArgument& arg = expr.subExpressions[i];
				if (arg.type == SSAArgType::eId && arg.location == SSALocation::eReg) {
					printf("%s <- ", arch->getRegister(arg.locref.refId)->name.cstr());
					resolveArg(arg);
					printf(", ");
				}
			}
			printf(")");
		}break;
		case SSAExprType::eReturn: {
			printf("Return ");
			printf("(");
			for (size_t i = 0; i < expr.subExpressions.size(); i++) {
				SSAArgument& arg = expr.subExpressions[i];
				if (arg.location == SSALocation::eReg) {
					printf("%s: ", arch->getRegister(arg.locref.refId)->name.cstr());
				}
				resolveArg(arg);
				if (i + 1 != expr.subExpressions.size())
					printf(", ");
			}
			printf(")");
		}break;
		case SSAExprType::eSyscall: {
			printf("Syscall ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eTrap: {
			printf("Trap ");
			resolveArgs(expr);
		}break;

		case SSAExprType::ePhi: {
			printf("Phi ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eAssign: {
			resolveArg(expr.subExpressions[0]);
		}break;

		case SSAExprType::eJmp: {
			SSAArgument& blockarg = expr.subExpressions[0];
			if (blockarg.type == SSAArgType::eOther && blockarg.location == SSALocation::eBlock)
				printf("goto L%d", blockarg.locref.refId);
		}break;
		case SSAExprType::eCJmp: {
			for (size_t i = 1; i < expr.subExpressions.size(); i += 2) {
				if (i > 1)
					printf("else ");
				printf("if(");
				resolveArg(expr.subExpressions[i]);
				printf(")");
				SSAArgument& blockarg = expr.subExpressions[i - 1];
				if (blockarg.type == SSAArgType::eOther && blockarg.location == SSALocation::eBlock)
					printf(" goto L%d", blockarg.locref.refId);
				else {
					printf(" goto ");
					resolveArg(blockarg);
				}
			}
		}break;
		case SSAExprType::eMemAccess: {
			printf("MemAccess ");
			resolveArgs(expr);
		}break;
		case SSAExprType::eStore: {
			SSAArgument& valueArg = expr.subExpressions[2];

			resolveMemArg(expr.subExpressions[1], valueArg.size);
			printf(" = ");
			resolveArg(valueArg);
		}break;
		case SSAExprType::eLoad: {
			resolveMemArg(expr.subExpressions[1], expr.size);
		}break;
		}
		if (expr.type != SSAExprType::eInput && expr.type != SSAExprType::eCall)
			printf(")");
	}
	void SSATransformToC::printExpression(SSAExpression& expr) {
		if (expr.type == SSAExprType::eOutput || expr.type == SSAExprType::ePhi || expr.type == SSAExprType::eMemOutput)
			return;
		resolveIds.insert(expr.id);
		printIndent(1);
		if (expr.type != SSAExprType::eCall && !EXPR_HAS_SIDEEFFECT(expr.type)) {
			if (UnifiedExprs* uExprs = getUnifiedExpr(expr.uniqueId)) {
				printf("var%d = ", uExprs->id);
			}
			else if (resolveIds.find(expr.id) != resolveIds.end()) {
				printf("tmp%d = ", expr.id);
			}
		}
		resolveExpression(expr);
		puts("");
	}

	bool SSATransformToC::doTransformation (Binary* binary, Function* function){
		printf("Transform To C\n");

		this->binary = binary;
		this->function = function;

		//function->print(binary->arch);
		Symbol *sym = binary->getSymbol(function->symbolref);

		printf("Structure Analysis\n");
		HSet<HId> visited;
		for (SSABB& bb : function->ssaRep.bbs)
			visited.insert(bb.id);
		ControlStruct g_struct(ControlStructType::GLOBAL);
		for (SSABB& bb : function->ssaRep.bbs)
			g_struct.contained_blocks.insert(bb.id);
		analyzeStructure(g_struct, 1);
		g_struct.print(1);
		arguments.clear();
		resolveIds.clear();
		resolveBBs.clear();
		if(sym)
			printf("Function: %s\n", sym->name.cstr());
		printf("Calling Functions: ");
		for (uint64_t addr : function->funcsCall) {
			printf("0x%x ", addr);
		}
		printf("\n");
		printf("CalledFunctions: ");
		for (uint64_t addr : function->funcsCalled) {
			printf("0x%x ", addr);
		}
		printf("\n");
		{
			SSABB& bb = function->ssaRep.bbs[1];
			for (HId id : bb.exprIds) {
				SSAExpression& expr = function->ssaRep.expressions[id];
				if (expr.type == SSAExprType::eInput) {
					if (expr.location == SSALocation::eReg) {
						CArgument arg = { 0, expr.id, { binary->arch->getRegister(expr.locref.refId)->name.cstr(), expr.locref.refId } };
						arguments.push_back(arg);
					}
				}
			}
			for (SSABB& bb : function->ssaRep.bbs) {
				for (HId id : bb.outBlocks) {
					if (bb.fallthroughId != id || bb.id + 1 != id) {
						resolveBBs.insert(id);
					}
				}
			}

			printIndent(1);
			printf("Input (");
			for (CArgument arg : arguments) {
				printf("arg%d <- %s ", arg.id, arg.regRef.name.cstr());
			}
			puts(")\n");

			unifiedExprs.clear();

			for (SSAExpression& expr : function->ssaRep.expressions) {
				if (expr.type == SSAExprType::ePhi) {
					HId foundId = 0;
					UnifiedExprs* uExprs = getUnifiedExpr(expr.uniqueId);
					if (uExprs) {
						foundId = uExprs->id;
					}
					else {
						foundId = unifiedExprs.emplace_back();
					}

					for (SSAArgument& arg : expr.subExpressions) {
						if (arg.type == SSAArgType::eId) {
							SSAExpression& argExpr = function->ssaRep.expressions[arg.ssaId];
							if (argExpr.type == SSAExprType::ePhi) {
								for (auto it = unifiedExprs.begin(); it != unifiedExprs.end();) {
									if (it->id != foundId && it->occuringIds.find(expr.uniqueId) != it->occuringIds.end()) {
										unifiedExprs.get(foundId)->occuringIds.insert(it->occuringIds.begin(), it->occuringIds.end());
										it = unifiedExprs.erase(it);
										continue;
									}
									++it;
								}
							}
							unifiedExprs.get(foundId)->occuringIds.insert(argExpr.uniqueId);
						}
					}
					unifiedExprs.get(foundId)->occuringIds.insert(expr.uniqueId);

					resolveIds.insert(expr.id);
					for (SSAArgument& arg : expr.subExpressions) {
						if (arg.type == SSAArgType::eId) {
							resolveIds.insert(arg.ssaId);
						}
					}
				}

				if (expr.type == SSAExprType::eOutput) {
					resolveIds.insert(expr.id);
				}
			}

		}
		
		for (size_t index = 1; index < function->ssaRep.bbs.list.size(); ++index) {
			printBasicBlock(function->ssaRep.bbs.list[index]);
		}
		return false;
	}
}

