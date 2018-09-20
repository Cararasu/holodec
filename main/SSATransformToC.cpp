#include "SSATransformToC.h"


namespace holodec{


	void printExprType(SSAExpression& expr) {
		switch (expr.exprtype) {
		case SSAType::eInt:
			printf("s%d ", expr.size);
			break;
		case SSAType::eUInt:
			printf("u%d ", expr.size);
			break;
		case SSAType::eFloat:
			printf("f%d ", expr.size);
			break;
		case SSAType::ePc:
			printf("pc%d ", expr.size);
			break;
		case SSAType::eMemaccess:
			printf("mem%d ", expr.size);
			break;
		}

	}
	void ControlStruct::print(int indent) {
		printIndent(indent);
		switch (type) {
		case ControlStructType::SEQUENCE:
			printf("SEQUENCE");
			break;
		case ControlStructType::BRANCH:
			printf("BRANCH");
			break;
		case ControlStructType::LOOP:
			printf("LOOP");
			break;
		case ControlStructType::GLOBAL:
			printf("GLOBAL");
			break;
		}
		printf(" Head: %d -> Exit %d\n", head_block, main_exit);
		printIndent(indent);
		printf("Inputs: ");
		for (IOBlock ioBlock : input_blocks)
			printf("%d(%d), ", ioBlock.blockId, ioBlock.count);
		printf("\n");
		printIndent(indent);
		printf("Contains: ");
		for (HId id : contained_blocks)
			printf("%d, ", id);
		printf("\n");
		printIndent(indent);
		printf("Exits: ");
		for (IOBlock ioBlock : exit_blocks)
			printf("%d(%d), ", ioBlock.blockId, ioBlock.count);
		printf("\n");
		printIndent(indent);
		printf("Children\n");
		for (ControlStruct child : child_struct)
			child.print(indent + 1);
	}

	bool SSATransformToC::analyzeLoop(ControlStruct* loopStruct) {
		ControlStruct* tmpLoopStruct = loopStruct;
		while (tmpLoopStruct->parent_struct) {
			if (tmpLoopStruct->parent_struct->head_block == loopStruct->head_block)
				return false;
			tmpLoopStruct = tmpLoopStruct->parent_struct;
		}

		HSet<HId> visitedBlocks, loopBlocks;
		SSABB* basicBlock = &function->ssaRep.bbs[loopStruct->head_block];
		analyzeLoopFor(loopStruct->head_block, visitedBlocks, loopStruct);//mark forward
		analyzeLoopBack(loopStruct->head_block, visitedBlocks, loopStruct);//gather backwards

		//we split nodes that have multiple outputs and inputs into 2 distinct blocks, which means a loop always has at least 2 nodes
		//if only 1 node is in the set then the no loop was found
		if (loopStruct->contained_blocks.size() <= 1) {
			SSABB& headbb = function->ssaRep.bbs[loopStruct->head_block];
			//in case that one block loops onto itself and has no outnode
			//then the node is not split and we do not see it as a loop
			//as an example this instruction:
			// 0xf00d: jmp 0xf00d
			//causes such an event
			if (headbb.outBlocks.find(headbb.id) == headbb.outBlocks.end()) {
				return false;
			}
		}

		for (const HId& id : loopStruct->contained_blocks) {
			SSABB* basicBlock = &function->ssaRep.bbs[id];
			for (HId id : basicBlock->inBlocks) {
				if (loopStruct->contained_blocks.find(id) == loopStruct->contained_blocks.end()) {
					loopStruct->input_blocks.insert(basicBlock->id).first->count++;
				}
			}
			for (HId id : basicBlock->outBlocks) {
				if (loopStruct->contained_blocks.find(id) == loopStruct->contained_blocks.end()) {
					loopStruct->exit_blocks.insert(id).first->count++;
				}
			}
		}
		for (auto it = loopStruct->exit_blocks.begin(); it != loopStruct->exit_blocks.end(); ) {
			//go through the exitblocks and add blocks that are dominated by the loop
			//as long as there are more than one exit
			//builds a near dominator-frontier
			if (loopStruct->exit_blocks.size() == 1)
				break;
			SSABB* block = &function->ssaRep.bbs[it->blockId];
			bool canAddBlock = true;
			for (auto inIt = block->inBlocks.begin(); inIt != block->inBlocks.end(); inIt++) {
				if (loopStruct->exit_blocks.find(*inIt) == loopStruct->exit_blocks.end()) {
					canAddBlock = false;
					break;
				}
			}
			if (canAddBlock) {
				it = loopStruct->exit_blocks.erase(it);
				for (HId id : block->outBlocks) {
					auto newit = loopStruct->exit_blocks.insert(id).first;
					newit->count++;
					if (*newit < *it)
						it = newit;
				}
				continue;
			}
			++it;
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
		if (controlStruct.type == ControlStructType::SEQUENCE) {//has no child nodes
			return;
		}
		if (controlStruct.type == ControlStructType::BRANCH) {
			if (controlStruct.head_block == start_block_id) {
				SSABB* basicBlock = &function->ssaRep.bbs[start_block_id];
				for (HId id : basicBlock->outBlocks) {
					if(id != start_block_id)
						analyzeStructure(controlStruct, id);
				}
				return;
			}
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
			if(controlStruct.input_blocks.find(start_block_id) == controlStruct.input_blocks.end() && analyzeLoop(&createdStruct)){
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
			createdStruct.input_blocks.insert(basicBlock->id).first->count = static_cast<uint32_t>(basicBlock->inBlocks.size());
			createdStruct.contained_blocks.insert(basicBlock->id);
			for (auto it = basicBlock->outBlocks.begin(); it != basicBlock->outBlocks.end(); ++it) {
				createdStruct.exit_blocks.insert(*it).first->count++;
			}
		}
		if (!created && basicBlock->outBlocks.size() <= 1) {
			created = true;
			createdStruct.type = ControlStructType::SEQUENCE;
			createdStruct.parent_struct = &controlStruct;
			createdStruct.input_blocks.insert(basicBlock->id).first->count = static_cast<uint32_t>(basicBlock->inBlocks.size());
			createdStruct.contained_blocks.insert(basicBlock->id);

			SSABB* tBB = basicBlock;
			do {
				createdStruct.contained_blocks.insert(tBB->id);
				if (tBB->outBlocks.size() == 0) {
					tBB = nullptr;
					break;
				}
				tBB = &function->ssaRep.bbs[*tBB->outBlocks.begin()];

			} while (tBB->inBlocks.size() == 1 && tBB->outBlocks.size() <= 1);
			if (tBB)
				createdStruct.exit_blocks.insert(tBB->id).first->count++;
		}
		if (created) {
			bool changed = true;
			while (changed && createdStruct.exit_blocks.size() > 1) {
				changed = false;
				for (auto it = createdStruct.exit_blocks.begin(); it != createdStruct.exit_blocks.end(); ++it) {
					if (createdStruct.contained_blocks.find(it->blockId) != createdStruct.contained_blocks.end()) {//exit block is not in contained blocks
						continue;
					}
					if (controlStruct.contained_blocks.find(it->blockId) == controlStruct.contained_blocks.end()) {//exit block is in parent contained blocks
						continue;
					}
					SSABB* basicBlock = &function->ssaRep.bbs[it->blockId];
					bool noHead = false;
					for (HId id : basicBlock->inBlocks) {//if one input is not in the contained blocks
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

			controlStruct.child_struct.push_back(createdStruct);
			for (const IOBlock& block : createdStruct.input_blocks) {
				analyzeStructure(controlStruct.child_struct.back(), block.blockId);
			}
			for (const IOBlock& block : createdStruct.exit_blocks) {
				analyzeStructure(controlStruct, block.blockId);
			}
		}
		
	}
	bool SSATransformToC::shouldResolve(SSAExpression& expr) {
		resolveIds.insert(expr.id);
		return true;
		if (expr.type == SSAExprType::eLoad)//for ordering sake until a comprehensive DFA is implemented
			return true;
		if (resolveIds.find(expr.id) != resolveIds.end()) {
			return true;
		}
		if (expr.refs.size() > 1) {
			return true;
		}
		if (EXPR_HAS_SIDEEFFECT(expr.type) || expr.type == SSAExprType::eStore) {
			return true;
		}
		return false;
	}


	void SSATransformToC::resolveArgs(SSAExpression& expr, const char* delimiter) {
		printf("(");
		for (size_t i = 0; i < expr.subExpressions.size(); i++) {
			SSAArgument& arg = expr.subExpressions[i];
			resolveArg(arg);
			if(i + 1 != expr.subExpressions.size())
				printf("%s", delimiter);
		}
		printf(")");
	}
	UnifiedExprs* SSATransformToC::getUnifiedExpr(HId uId) {
		for (UnifiedExprs& exprs : unifiedExprs) {
			if (!exprs.id) continue;
			if (exprs.occuringIds.find(uId) != exprs.occuringIds.end()) {
				return &exprs;
			}
		}
		return nullptr;
	}
	bool SSATransformToC::resolveArgVariable(SSAExpression& expr, bool write) {
		auto it = argumentIds.find(expr.id);
		if (!shouldResolve(expr))
			return false;
		if (it != argumentIds.end()) {
			printf("arg%d", it->second);
			return true;
		}
		else if (UnifiedExprs* uExprs = getUnifiedExpr(expr.uniqueId)) {
			if (write) {
				printf("var%d, ", uExprs->id);
			}
			else if (uExprs->ssaId == expr.id)  {
				printf("var%d", uExprs->id);
				return true;
			}
		}
		printf("tmp%d", expr.id);
		return true;
	}
	void SSATransformToC::resolveArg(SSAArgument& arg) {

		SSAExpression* subExpr = arg.type == SSAArgType::eId ? &function->ssaRep.expressions[arg.ssaId] : nullptr;

		switch (arg.type) {
		case SSAArgType::eUndef:
			printf("undef");
			break;
		case SSAArgType::eId: {
			if (!resolveArgVariable(*subExpr, false)) {
				resolveExpression(*subExpr);
			}
		}break;
		}
	}
	bool SSATransformToC::resolveExpression(SSAExpression& expr) {

		if (expr.type == SSAExprType::eBranch)
			return false;

		if (expr.type != SSAExprType::eInput && expr.type != SSAExprType::eCall && !EXPR_HAS_SIDEEFFECT(expr.type))
			printf("(");
		switch (expr.type) {
		case SSAExprType::eInvalid:
			return false;
		case SSAExprType::eLabel:
			return false;
		case SSAExprType::eUndef:
			return false;
		case SSAExprType::eNop:
			return false;
		case SSAExprType::eOp: {
			if (expr.opType == SSAOpType::eNot) {
				printf("!(");

				for (size_t i = 0; i < expr.subExpressions.size(); ++i) {
					if (i > 0)
						printf(",");
					SSAArgument& arg = expr.subExpressions[i];
					resolveArg(arg);
				}
				printf(")");
			}
			else {
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
						case SSAOpType::eBAnd:
							printf(" & ");
							break;
						case SSAOpType::eBOr:
							printf(" | ");
							break;
						case SSAOpType::eBXor:
							printf(" ^ ");
							break;
						case SSAOpType::eBNot:
							printf(" ~ ");
							break;
						case SSAOpType::eShr:
							printf(" >> ");
							break;
						case SSAOpType::eShl:
							printf(" << ");
							break;
						case SSAOpType::eRor:
							printf(" >>> ");
							break;
						case SSAOpType::eRol:
							printf(" <<< ");
							break;
						default:
							printf(" op ");
							break;
						}
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
			printf("-%d", expr.flagbit);
			printf("(");
			resolveArg(expr.subExpressions[0]);
			printf(")");
			break;
		case SSAExprType::eBuiltin:{
			printf("%s ", arch->getBuiltin(expr.builtinId)->name.cstr());
			resolveArgs(expr);
		}break;
		case SSAExprType::eSplit: {
			if (expr.offset) {
				printf("(");
			}
			SSAExpression& subexpr = function->ssaRep.expressions[expr.subExpressions[0].ssaId];
			if (expr.size == subexpr.size) {
				resolveArg(expr.subExpressions[0]);
			}
			else {
				printExprType(expr);
				resolveArg(expr.subExpressions[0]);
			}
			if (expr.offset) {
				printf(" >> %d)", expr.offset);
			}
		}break;
		case SSAExprType::eAppend: {
			printf("(");
			uint32_t offset = 0;
			for (size_t i = 0; i < expr.subExpressions.size(); i++) {
				SSAArgument& arg = expr.subExpressions[i];
				resolveArg(arg);
				if(offset)
					printf(" << %d", offset);
				offset += function->ssaRep.expressions[arg.ssaId].size;
				if (i + 1 != expr.subExpressions.size())
					printf(" | ");
			}
			printf(")");
		}break;
		case SSAExprType::eCast: {
			printf("Cast[");
			printExprType(expr);
			printf("]");
			resolveArgs(expr);
		}break;
		case SSAExprType::eValue: {
			switch (expr.exprtype) {
			case SSAType::eUInt:
				printf("0x%lx", expr.uval);
				break;
			case SSAType::eInt:
				printf("%ld", expr.sval);
				break;
			case SSAType::eFloat:
				printf("0x%f", expr.fval);
				break;
			}
		}break;

		case SSAExprType::eInput:
			for (CArgument& arg : arguments) {
				if (arg.ssaId == expr.id) {
					printf("arg%d", arg.id);
				}
			}
			break;
		case SSAExprType::eOutput:
			return false;

		case SSAExprType::eCall: {
			for (HId id : expr.directRefs) {
				SSAExpression& refExpr = function->ssaRep.expressions[id];
				if (refExpr.type == SSAExprType::eOutput && refExpr.location == SSALocation::eReg) {
					printExprType(refExpr);
					resolveArgVariable(refExpr, true);
					printf(" <- %s, ", arch->getRegister(refExpr.locref.refId)->name.cstr());
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
				if (arg.location == SSALocation::eMem) {
					continue;
				}
				if (arg.location == SSALocation::eReg) {
					RegisterState* state = function->usedRegStates.getRegisterState(arg.locref.refId);//reverse check if the argument is used outside in another function
					if (!function->exported && !state || !state->flags.contains(UsageFlags::eRead)) {
						continue;
					}
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
			resolveArgVariable(expr, false);
		}break;
		case SSAExprType::eAssign: {
			resolveArg(expr.subExpressions[0]);
		}break;
		case SSAExprType::eStore: {
			SSAArgument& memArg = expr.subExpressions[0];
			SSAArgument& ptrArg = expr.subExpressions[1];
			SSAArgument& valueArg = expr.subExpressions[2];
			SSAExpression* valexpr = find_baseexpr(&function->ssaRep, valueArg);
			printf("%s[", arch->getMemory(memArg.locref.refId)->name.cstr());
			printExprType(*valexpr);
			printf(", ");
			resolveArg(ptrArg);
			printf("] = ");
			resolveArg(valueArg);
		}break;
		case SSAExprType::eLoad: {
			SSAArgument& memArg = expr.subExpressions[0];
			SSAArgument& ptrArg = expr.subExpressions[1];

			printf("%s[", arch->getMemory(memArg.locref.refId)->name.cstr());
			printExprType(expr);
			printf(", ");
			resolveArg(ptrArg);
			printf("]");
		}break;
		}
		if (expr.type != SSAExprType::eInput && expr.type != SSAExprType::eCall && !EXPR_HAS_SIDEEFFECT(expr.type))
			printf(")");
		return true;
	}
	bool SSATransformToC::printExpression(SSAExpression& expr, uint32_t indent) {
		if (expr.type == SSAExprType::eOutput || expr.type == SSAExprType::eInput || expr.type == SSAExprType::eMemOutput || expr.type == SSAExprType::eBranch)
			return false;
		UnifiedExprs* uExprs = getUnifiedExpr(expr.uniqueId);
		resolveIds.insert(expr.id);
		printIndent(indent);
		if (uExprs && expr.type != SSAExprType::ePhi) {
			printExprType(expr);
			resolveArgVariable(expr, true);
			printf(" = ");
			uExprs->ssaId = expr.id;
			resolveArgVariable(expr, false);
			return true;
		}
		if (expr.type != SSAExprType::eCall && expr.type != SSAExprType::eStore && !EXPR_HAS_SIDEEFFECT(expr.type)) {
			printExprType(expr);
			resolveArgVariable(expr, true);
			printf(" = ");
		}
		bool res = resolveExpression(expr);
		if (uExprs) {
			uExprs->ssaId = expr.id;
			return true;
		}
		return res;
	}
	ControlStruct* getStructFromHead(ControlStruct* controlStruct, HId headId) {
		for (ControlStruct& subStruct : controlStruct->child_struct) {
			if (subStruct.head_block == headId)// || subStruct.contained_blocks.find(headId) != subStruct.contained_blocks.end())
				return &subStruct;
		}
		return nullptr;
	}

	bool resolveEscapeLoop(ControlStruct* controlStruct, HId nextBlockId, uint32_t indent) {
		if (controlStruct->type == ControlStructType::LOOP) {
			if (controlStruct->head_block == nextBlockId) {
				printIndent(indent); printf("continue;\n");
				return true;
			}
			else if (controlStruct->main_exit == nextBlockId) {
				printIndent(indent); printf("break;\n");
				return true;
			}
		}
		else if(controlStruct->parent_struct){
			return resolveEscapeLoop(controlStruct->parent_struct, nextBlockId, indent);
		}
		return false;
	}

	void SSATransformToC::resolveBlockArgument(ControlStruct* controlStruct, SSAArgument& arg, std::set<HId>& printed, uint32_t indent) {
		if (arg.type == SSAArgType::eBlock) {
			if (arg.ssaId != controlStruct->main_exit) {
				if (controlStruct->contained_blocks.find(arg.ssaId) == controlStruct->contained_blocks.end()) {
					if (controlStruct->main_exit != arg.ssaId) {
						if (!resolveEscapeLoop(controlStruct, arg.ssaId, indent)) {
							printIndent(indent); printf("goto L%d\n", arg.ssaId);
						}
					}
				}
				else {
					ControlStruct* subStruct = getStructFromHead(controlStruct, arg.ssaId);
					if (subStruct)
						printControlStruct(subStruct, function->ssaRep.bbs[subStruct->head_block], printed, indent);
					else if (controlStruct->main_exit != arg.ssaId)  {
						resolveEscapeLoop(controlStruct, arg.ssaId, indent);
						printIndent(indent); printf("goto L%d\n", arg.ssaId);
					}
					else {
						resolveEscapeLoop(controlStruct, arg.ssaId, indent);
						//goto to the main exit
					}
				}
			}
			else {
				resolveEscapeLoop(controlStruct, arg.ssaId, indent);
				//main exit
			}
		}
		else {
			printIndent(indent + 1); printf("goto "); resolveArg(arg); printf(";\n");
		}
	}
	void SSATransformToC::resolveBranchExpr(ControlStruct* controlStruct, SSAExpression& expr, std::set<HId>& printed, uint32_t indent) {
		if (expr.type == SSAExprType::eBranch) {
			/*if (expr.subExpressions.size() == 3 &&
				expr.subExpressions[0].type == SSAArgType::eOther && expr.subExpressions[0].location == SSALocation::eBlock && 
				(controlStruct->type == ControlStructType::LOOP || (controlStruct->type != ControlStructType::LOOP && expr.subExpressions[].locref.refId == controlStruct->main_exit))) {
				//special case where the first jump leads to the end of the branch
				//then we invert the if and only print the original else block
				printIndent(indent);
				printf("if(!");
				resolveArg(expr.subExpressions[1]); 
				printf(") {\n");
				resolveBlockArgument(controlStruct, expr.subExpressions[2], printed, indent + 1);
				printIndent(indent); printf("}\n");
			}
			else */if (expr.subExpressions.size() == 1) {
				SSAArgument& blockarg = expr.subExpressions[0];
				resolveBlockArgument(controlStruct, blockarg, printed, indent);
			}
			else {
				for (size_t i = 1; i < expr.subExpressions.size(); i += 2) {
					printIndent(indent);
					if (i > 1)
						printf("else ");
					printf("if(");
					resolveArg(expr.subExpressions[i]);
					printf(") {\n");
					SSAArgument& blockarg = expr.subExpressions[i - 1];
					resolveBlockArgument(controlStruct, blockarg, printed, indent + 1);
					printIndent(indent); printf("}\n");
				}
				//if (!(expr.subExpressions.back().type == SSAArgType::eOther && expr.subExpressions.back().location == SSALocation::eBlock && 
				//	(controlStruct->type == ControlStructType::LOOP || (controlStruct->type != ControlStructType::LOOP && expr.subExpressions.back().locref.refId == controlStruct->main_exit)))) {
					//TODO also check for empty blocks
					if (expr.subExpressions.size() > 1) {
						printIndent(indent); printf("else {\n");
					}
					resolveBlockArgument(controlStruct, expr.subExpressions.back(), printed, indent + 1);
					if (expr.subExpressions.size() > 1) {
						printIndent(indent); printf("}\n");
					}
				//}
			}
		}
		else if (expr.type != SSAExprType::eReturn) {
			printf("Branch Block with no Branch at the end\n");
		}
	}
	void SSATransformToC::resolveBlock(ControlStruct* controlStruct, SSABB& bb, std::set<HId>& printed, uint32_t indent) {
		printIndent(indent); printf("Label L%d:\n", bb.id);
		if (bb.inBlocks.size() > 1) {
			//printIndent(indent); printf("Label L%d:\n", theBB->id);
		}
		if (printed.find(bb.id) != printed.end()) {
			printIndent(indent); printf("goto L%d;\n", bb.id);
			return;
		}
		for (HId id : bb.exprIds) {
			SSAExpression& expr = function->ssaRep.expressions[id];
			if (shouldResolve(expr)) {
				if(printExpression(expr, indent))
					printf("\n");
			}
		}
		printed.insert(bb.id);
	}
	void SSATransformToC::printControlStruct(ControlStruct* controlStruct, SSABB& bb, std::set<HId>& printed, uint32_t indent) {
		if (!controlStruct || printed.find(controlStruct->head_block) != printed.end())
			return;
		switch (controlStruct->type) {
		case ControlStructType::SEQUENCE: {
			SSABB* theBB = &bb;
			SSABB* endBB = nullptr;
			while (controlStruct->contained_blocks.find(theBB->id) != controlStruct->contained_blocks.end()) {

				resolveBlock(controlStruct, *theBB, printed, indent);
				endBB = theBB;
				if (theBB->outBlocks.size() != 1){
					break;
				}
				theBB = &function->ssaRep.bbs[*theBB->outBlocks.begin()];
				if (printed.find(theBB->id) != printed.end()) {
					break;
				}
			}
			if (endBB) {
				resolveBranchExpr(controlStruct, function->ssaRep.expressions[endBB->exprIds.back()], printed, indent);
			}
		} break;
		case ControlStructType::BRANCH: {
			resolveBlock(controlStruct, function->ssaRep.bbs[controlStruct->head_block], printed, indent);
			resolveBranchExpr(controlStruct, function->ssaRep.expressions[function->ssaRep.bbs[controlStruct->head_block].exprIds.back()], printed, indent);
		} break;
		case ControlStructType::LOOP: {
			printIndent(indent); printf("loop {\n");
			ControlStruct* subStruct = getStructFromHead(controlStruct, controlStruct->head_block);
			if (subStruct)
				printControlStruct(subStruct, function->ssaRep.bbs[subStruct->head_block], printed, indent + 1);
			else {
				printIndent(indent + 1); printf("goto L%d\n", controlStruct->head_block);
			}
			for (ControlStruct& cStruct : controlStruct->child_struct) {
				if (printed.find(cStruct.head_block) == printed.end()) {
					printControlStruct(&cStruct, function->ssaRep.bbs[cStruct.head_block], printed, indent + 1);
				}
			}
			printIndent(indent); printf("}\n");
		} return;
		case ControlStructType::GLOBAL: {
			printControlStruct(&controlStruct->child_struct[0], function->ssaRep.bbs[controlStruct->child_struct[0].head_block], printed, indent + 1);
		}break;
		}
		if (controlStruct->parent_struct && controlStruct->main_exit) {
			if (controlStruct->parent_struct->contained_blocks.find(controlStruct->main_exit) != controlStruct->parent_struct->contained_blocks.end()) {
				ControlStruct* subStruct = getStructFromHead(controlStruct->parent_struct, controlStruct->main_exit);
				if (subStruct)
					printControlStruct(subStruct, function->ssaRep.bbs[subStruct->head_block], printed, indent);
				else {
					printIndent(indent); printf("goto L%d\n", controlStruct->main_exit);
				}
			}
		}
		for (ControlStruct& cStruct : controlStruct->child_struct) {
			if (printed.find(cStruct.head_block) == printed.end()) {
				printControlStruct(&cStruct, function->ssaRep.bbs[cStruct.head_block], printed, indent + 1);
			}
		}
	}

	void setParentStructs(ControlStruct* controlStruct) {
		for (ControlStruct& child_struct : controlStruct->child_struct) {
			child_struct.parent_struct = controlStruct;
			setParentStructs(&child_struct);
		}
	}

	//consolidate branches and loops so that if(cond){while(cond){doStuff;}} gets correctly handled and the loop gets pushed into the branch
	//we only handle loops after branches because they are the cases that are handled by the normal structure-analyzing
	void SSATransformToC::consolidateBranchLoops(ControlStruct* controlStruct) {
		bool changed = false;
		do{
			changed = false;
			for (ControlStruct& childStruct : controlStruct->child_struct) {
				//ignore non-branches and in case of one exitblock we are already finished with consolidating branches
				if (childStruct.type != ControlStructType::BRANCH || childStruct.exit_blocks.size() <= 1)
					continue;

				for (const IOBlock& exitBlock : childStruct.exit_blocks) {
					//if we exit the block completely continue
					if (controlStruct->contained_blocks.find(exitBlock.blockId) == controlStruct->contained_blocks.end()) {
						continue;
					}
					//search where the control flow goes next
					auto innerInputIt = controlStruct->child_struct.begin();
					for (; innerInputIt != controlStruct->child_struct.end(); ++innerInputIt) {
						if (innerInputIt->type == ControlStructType::LOOP && innerInputIt->input_blocks.find(exitBlock.blockId) != innerInputIt->input_blocks.end())
							break;
					}
					if (innerInputIt != controlStruct->child_struct.end()) {
						//all inputs 
						bool canNotFuse = false;
						for (const IOBlock& aBlock : innerInputIt->input_blocks) {
							for (ControlStruct& subStruct : controlStruct->child_struct) {
								canNotFuse |= subStruct.exit_blocks.find(aBlock.blockId) != subStruct.exit_blocks.end() && &subStruct != &childStruct;
							}
						}
						if (!canNotFuse) {
							for (auto inputBlockIt = innerInputIt->input_blocks.begin(); inputBlockIt != innerInputIt->input_blocks.end(); ++inputBlockIt) {
								if ((childStruct.exit_blocks.find(inputBlockIt->blockId)->count -= inputBlockIt->count) == 0)
									childStruct.exit_blocks.erase(inputBlockIt->blockId);
							}
							childStruct.contained_blocks.insert(innerInputIt->contained_blocks.begin(), innerInputIt->contained_blocks.end());
							for (const IOBlock& ioBlock : innerInputIt->exit_blocks) {
								if (childStruct.contained_blocks.find(ioBlock.blockId) == childStruct.contained_blocks.end()) {
									childStruct.exit_blocks.insert(ioBlock.blockId).first->count += ioBlock.count;
								}
							}
							innerInputIt->parent_struct = &childStruct;
							childStruct.child_struct.push_back(*innerInputIt);
							controlStruct->child_struct.erase(innerInputIt);
							changed = true;

							for (auto it = childStruct.exit_blocks.begin(); it != childStruct.exit_blocks.end(); ++it) {
								if (it->count == 0) {
									it = childStruct.exit_blocks.erase(it);
								}
							}
							for (auto it = childStruct.input_blocks.begin(); it != childStruct.input_blocks.end(); ++it) {
								if (it->count == 0) {
									it = childStruct.input_blocks.erase(it);
								}
							}
							for (ControlStruct& subStruct : childStruct.child_struct.back().child_struct) {
								subStruct.parent_struct = &childStruct.child_struct.back();
							}
							break;
						}
					}
					if (changed)
						break;
				}
				if (changed)
					break;
			}
		} while (changed);
		for (ControlStruct& childStruct : controlStruct->child_struct) {
			consolidateBranchLoops(&childStruct);
		}

		uint32_t maxExits = 0;
		for (const IOBlock& exit_block : controlStruct->exit_blocks) {
			if (exit_block.count > maxExits) {
				controlStruct->main_exit = exit_block.blockId;
				maxExits = exit_block.count;
			}
		}
		uint32_t maxInputs = 0;
		for (const IOBlock& input_block : controlStruct->input_blocks) {
			if (input_block.count > maxInputs) {
				controlStruct->head_block = input_block.blockId;
				maxInputs = input_block.count;
			}
		}
	}
	bool SSATransformToC::doTransformation (Binary* binary, Function* function){
		printf("Transform To C\n");

		this->binary = binary;
		this->function = function;

		//function->print(binary->arch);
		Symbol *sym = binary->getSymbol(function->symbolref);

		if (sym)
			printf("Function: %s\n", sym->name.cstr());

		{//split blocks, so that they have either exactly one input ore one output
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
								SSAExpression& branchExpr = function->ssaRep.expressions[loopBB.exprIds.back()];

								auto it = loopBB.outBlocks.find(oldBlockId);
								if (it != loopBB.outBlocks.end()) {
									loopBB.outBlocks.erase(it);
								}
								loopBB.outBlocks.insert(newbb.id);
								for (SSAArgument& arg : branchExpr.subExpressions) {
									if (arg.type == SSAArgType::eBlock && arg.ssaId == oldBlockId)
										arg.ssaId = newbb.id;
								}
							}

							SSAExpression branchExpr(SSAExprType::eBranch, arch->bitbase * arch->bytebase, SSAType::ePc);
							branchExpr.subExpressions = { SSAArgument::createBlock(oldBB.id) };
							function->ssaRep.addAtEnd(&branchExpr, &newbb);

							oldBB.inBlocks = { function->ssaRep.bbs.back().id };
						}
						changed = true;
						break;
					}
				}
			} while (changed);
		}

		//function->printSimple(binary->arch);
		//printf("Structure Analysis\n");
		ControlStruct g_struct = { ControlStructType::GLOBAL };
		g_struct.head_block = 1;
		for (SSABB& bb : function->ssaRep.bbs) {
			if(bb.inBlocks.size() == 0)
				g_struct.input_blocks.insert(bb.id).first->count++;
			g_struct.contained_blocks.insert(bb.id);
			if (bb.outBlocks.size() == 0)
				g_struct.exit_blocks.insert(bb.id).first->count++;
		}
		analyzeStructure(g_struct, 1);
		consolidateBranchLoops(&g_struct);
		setParentStructs(&g_struct);


		arguments.clear();
		argumentIds.clear();
		resolveIds.clear();
		resolveBBs.clear();
		{
			SSABB& bb = function->ssaRep.bbs[1];
			for (HId id : bb.exprIds) {
				SSAExpression& expr = function->ssaRep.expressions[id];
				if (expr.type == SSAExprType::eInput) {
					if (expr.location == SSALocation::eReg) {
						CArgument arg = { 0, expr.id, { binary->arch->getRegister(expr.locref.refId)->name.cstr(), expr.locref.refId } };
						arguments.push_back(arg);
						argumentIds.insert(std::make_pair(expr.id, static_cast<HId>(arguments.size())));
					}
				}
			}
			for (SSABB& bb : function->ssaRep.bbs) {
				for (HId id : bb.outBlocks) {
					if (bb.id + 1 != id) {
						resolveBBs.insert(id);
					}
				}
			}

			printIndent(1);
			printf("Input (");
			for (CArgument arg : arguments) {
				printf("arg%d <- %s ", arg.id, arg.regRef.name.cstr());
			}
			printf("){\n");

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
						unifiedExprs[foundId].occuringIds.insert(expr.uniqueId);
					}

					for (SSAArgument& arg : expr.subExpressions) {
						if (arg.type == SSAArgType::eId) {
							SSAExpression& argExpr = function->ssaRep.expressions[arg.ssaId];
							if (argExpr.type == SSAExprType::ePhi) {
								for (auto it = unifiedExprs.begin(); it != unifiedExprs.end();) {
									if (it->id && it->id != foundId && it->occuringIds.find(argExpr.uniqueId) != it->occuringIds.end()) {
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
		printf("\n");
		HSet<HId> visited;
		printControlStruct(&g_struct, function->ssaRep.bbs[1], visited, 1);

		printIndent(1);
		printf("}\n");
		for (HId id : resolveIds) {
			printf("%d, ", id);
		}
		printf("\n");

		return false;
	}
}
