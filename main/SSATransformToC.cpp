#include "SSATransformToC.h"


namespace holodec{

	//gather outputs
	//mark every nodes outwards of outputs
	//if there exists a node that has the same number of marks as 
	//


	bool SSATransformToC::analyzeLoop(ControlStruct* loopStruct) {
		ControlStruct* tmpLoopStruct = loopStruct;
		while (tmpLoopStruct->parent_struct) {
			if(tmpLoopStruct->parent_struct->head_block == loopStruct->head_block)
				return false;
			tmpLoopStruct = tmpLoopStruct->parent_struct;
		}

		HSet<HId> visitedBlocks, loopBlocks;
		SSABB* basicBlock = &function->ssaRep.bbs[loopStruct->head_block];
		for (HId id : basicBlock->outBlocks) {
			analyzeLoopFor(id, visitedBlocks, loopStruct);
		}
		for (HId id : basicBlock->inBlocks) {
			analyzeLoopBack(id, visitedBlocks, loopStruct);
		}
		if (loopStruct->contained_blocks.empty())
			return false;

		for (const HId& id : loopStruct->contained_blocks) {
			SSABB* basicBlock = &function->ssaRep.bbs[id];
			for (HId id : basicBlock->inBlocks) {
				auto it = loopStruct->contained_blocks.find(id);
				if (it == loopStruct->contained_blocks.end()) {
					loopStruct->input_blocks.insert(basicBlock->id).first->count++;
				}
			}
			for (HId id : basicBlock->outBlocks) {
				auto it = loopStruct->contained_blocks.find(id);
				if (it == loopStruct->contained_blocks.end()) {
					loopStruct->exit_blocks.insert(id).first->count++;
				}
			}
		}
		return true;
	}
	void SSATransformToC::analyzeLoopFor(HId bbId, HSet<HId>& visitedNodes, ControlStruct* loopStruct) {

		if (loopStruct->parent_struct && 
			(loopStruct->parent_struct->head_block == bbId || loopStruct->parent_struct->contained_blocks.find(bbId) == loopStruct->parent_struct->contained_blocks.end())){
			return;
		}
		if (visitedNodes.find(bbId) != visitedNodes.end()) {
			return;
		}
		visitedNodes.insert(bbId);

		SSABB* basicBlock = &function->ssaRep.bbs[bbId];
		for (HId id : basicBlock->outBlocks) {
			analyzeLoopFor(id, visitedNodes, loopStruct);
		}
	}
	void SSATransformToC::analyzeLoopBack(HId bbId, HSet<HId>& visitedNodes, ControlStruct* loopStruct) {

		if (loopStruct->parent_struct && 
			(loopStruct->parent_struct->head_block == bbId || loopStruct->parent_struct->contained_blocks.find(bbId) == loopStruct->parent_struct->contained_blocks.end())) {
			return;
		}
		if (visitedNodes.find(bbId) == visitedNodes.end()) {
			return;
		}
		if (loopStruct->contained_blocks.find(bbId) != loopStruct->contained_blocks.end()) {
			return;
		}
		loopStruct->contained_blocks.insert(bbId);
		SSABB* basicBlock = &function->ssaRep.bbs[bbId];
		for (HId id : basicBlock->inBlocks) {
			analyzeLoopBack(id, visitedNodes, loopStruct);
		}
		return;
	}
	void SSATransformToC::analyzeStructure(ControlStruct& controlStruct, HId start_block_id) {
		if (controlStruct.type != ControlStructType::LOOP) {
			if (controlStruct.head_block == start_block_id) {
				SSABB* basicBlock = &function->ssaRep.bbs[start_block_id];
				for (HId id : basicBlock->outBlocks) {
					if(id != start_block_id)
						analyzeStructure(controlStruct, id);
				}
				return;
			}
		}
		if (controlStruct.type == ControlStructType::SEQUENCE) {
			return;
		}
		if (controlStruct.contained_blocks.find(start_block_id) == controlStruct.contained_blocks.end())
			return;
		for (ControlStruct& child : controlStruct.child_struct) {
			if (child.contained_blocks.find(start_block_id) != child.contained_blocks.end()) {
				return;
			}
		}

		SSABB* basicBlock = &function->ssaRep.bbs[start_block_id];
		ControlStruct createdStruct;
		createdStruct.parent_struct = &controlStruct;
		createdStruct.head_block = start_block_id;
		bool created = false;
		if (basicBlock->inBlocks.size() > 1) {//Loop - Check
			created = true;
			createdStruct.type = ControlStructType::LOOP;
			//createdStruct.input_blocks.insert(start_block_id).first->count++;
			if(controlStruct.input_blocks.find(start_block_id) == controlStruct.input_blocks.end() && analyzeLoop(&createdStruct)){
				for (auto it = createdStruct.exit_blocks.begin(); it != createdStruct.exit_blocks.end(); ++it) {
					SSABB* block = &function->ssaRep.bbs[it->blockId];
					if (block->inBlocks.size() == 1 && block->outBlocks.size() <= 1) {
						createdStruct.contained_blocks.insert(it->blockId);
						it = createdStruct.exit_blocks.erase(it);
						if (block->outBlocks.size() == 1)
							createdStruct.exit_blocks.insert(block->outBlocks[0]).first->count++;
					}
				}
				uint32_t count = 0;
				for (const IOBlock& ioB : createdStruct.input_blocks) {
					if (ioB.count > count) {
						createdStruct.head_block = ioB.blockId;
						count = ioB.count;
					}
				}
			}
			else {
				createdStruct.child_struct.clear();
				createdStruct.contained_blocks.clear();
				createdStruct.exit_blocks.clear();
				createdStruct.input_blocks.clear();
				created = false;
			}
		}
		if (!created && basicBlock->outBlocks.size() > 1) {//Branch - Check
			created = true;
			createdStruct.type = ControlStructType::BRANCH;
			createdStruct.parent_struct = &controlStruct;
			createdStruct.input_blocks.insert(basicBlock->id).first->count = basicBlock->inBlocks.size();
			createdStruct.contained_blocks.insert(basicBlock->id);
			for (auto it = basicBlock->outBlocks.begin(); it != basicBlock->outBlocks.end(); ++it) {
				createdStruct.exit_blocks.insert(*it).first->count++;
			}
		}
		if (!created && basicBlock->outBlocks.size() <= 1) {
			created = true;
			createdStruct.type = ControlStructType::SEQUENCE;
			createdStruct.parent_struct = &controlStruct;
			createdStruct.input_blocks.insert(basicBlock->id).first->count = basicBlock->inBlocks.size();
			createdStruct.contained_blocks.insert(basicBlock->id);

			SSABB* tBB = basicBlock;
			do {
				createdStruct.contained_blocks.insert(tBB->id);
				if (tBB->outBlocks.size() == 0) {
					tBB = nullptr;
					break;
				}
				tBB = &function->ssaRep.bbs[tBB->outBlocks[0]];

			} while (tBB->inBlocks.size() == 1 && tBB->outBlocks.size() <= 1);
			if (tBB)
				createdStruct.exit_blocks.insert(tBB->id).first->count++;
		}
		if (created) {
			bool changed = true;
			while (changed && createdStruct.exit_blocks.size() > 1) {
				changed = false;
				for (auto it = createdStruct.exit_blocks.begin(); it != createdStruct.exit_blocks.end(); ++it) {
					if (createdStruct.contained_blocks.find(it->blockId) != createdStruct.contained_blocks.end()) {
						continue;
					}
					if (controlStruct.contained_blocks.find(it->blockId) == controlStruct.contained_blocks.end()) {
						continue;
					}
					SSABB* basicBlock = &function->ssaRep.bbs[it->blockId];
					bool noHead = false;
					for (HId id : basicBlock->inBlocks) {
						if (createdStruct.contained_blocks.find(id) == createdStruct.contained_blocks.end()) {
							noHead |= true;
						}
					}
					if (!noHead) {	
						changed = true;
						uint32_t count = it->count;
						it = createdStruct.exit_blocks.erase(it);
						createdStruct.contained_blocks.insert(basicBlock->id);
						for (HId id : basicBlock->outBlocks) {
							createdStruct.exit_blocks.insert(id).first->count += count;
						}
						break;
					}

				}
			}


			for (const IOBlock& block : createdStruct.input_blocks) {
				analyzeStructure(createdStruct, block.blockId);
			}
			controlStruct.child_struct.push_back(createdStruct);
			for (const IOBlock& block : createdStruct.exit_blocks) {
				analyzeStructure(controlStruct, block.blockId);
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
	ControlStruct* getStructFromHead(ControlStruct* controlStruct, HId headId) {
		for (ControlStruct& subStruct : controlStruct->child_struct) {
			if (subStruct.head_block == headId)
				return &subStruct;
		}
		return nullptr;
	}
	bool SSATransformToC::doTransformation (Binary* binary, Function* function){
		printf("Transform To C\n");

		this->binary = binary;
		this->function = function;

		//function->print(binary->arch);
		Symbol *sym = binary->getSymbol(function->symbolref);

		{
			bool changed = false;
			do {
				changed = false;
				for (SSABB& bb : function->ssaRep.bbs) {
					if (bb.inBlocks.size() != 1 && bb.outBlocks.size() != 1) {
						HId oldBlockId = bb.id;
						SSABB newbb;
						newbb.inBlocks = bb.inBlocks;
						newbb.outBlocks = { bb.id };
						function->ssaRep.bbs.push_back(newbb);
						{
							SSABB& newbb = function->ssaRep.bbs.back();
							SSABB& oldBB = function->ssaRep.bbs[oldBlockId];//reload
							for (HId id : oldBB.inBlocks) {
								SSABB& loopBB = function->ssaRep.bbs[id];//reload
								for (HId& outId : loopBB.outBlocks) {
									if (outId == oldBlockId) {
										outId = newbb.id;
									}
								}
							}
							oldBB.inBlocks = { function->ssaRep.bbs.back().id };
						}
						changed = true;
						break;
					}
				}
			} while (changed);
		}

		printf("Structure Analysis\n");
		HSet<HId> visited;
		for (SSABB& bb : function->ssaRep.bbs)
			visited.insert(bb.id);
		ControlStruct g_struct = { ControlStructType::GLOBAL };
		for (SSABB& bb : function->ssaRep.bbs) {
			if(bb.inBlocks.size() == 0)
				g_struct.input_blocks.insert(bb.id).first->count++;
			g_struct.contained_blocks.insert(bb.id);
			if (bb.outBlocks.size() == 0)
				g_struct.exit_blocks.insert(bb.id).first->count++;
		}
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
		/*std::set<HId> visited;
		printControlStruct(&g_struct, visited);*/
		for (size_t index = 1; index < function->ssaRep.bbs.list.size(); ++index) {
			printBasicBlock(function->ssaRep.bbs.list[index]);
		}
		return false;
	}
}

