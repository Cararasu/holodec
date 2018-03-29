#ifndef SSATRANSFORMTOC_H
#define SSATRANSFORMTOC_H

#include "SSATransformer.h"
namespace holodec {

	struct CArgument {
		HId id;
		HId ssaId;
		StringRef regRef;
	};
	struct UnifiedExprs {
		HId id;
		std::set<HId> occuringIds;
	};
	enum class ControlStructType{
		TAIL = 1,
		SEQUENCE,
		BRANCH,
		LOOP,
		GLOBAL,
	};
	struct IOBlock {
		HId blockId;
		mutable uint32_t count;

		IOBlock(HId blockId) : blockId(blockId), count(0) {}
		IOBlock(HId blockId, uint32_t count) : blockId(blockId), count(count) {}
	};
	inline bool operator<(const IOBlock& lhs, const IOBlock& rhs) {
		return lhs.blockId < rhs.blockId;
	}
	inline bool operator==(const IOBlock& lhs, const IOBlock& rhs) {
		return lhs.blockId == rhs.blockId;
	}

	struct ControlStruct {
		ControlStructType type;
		HId head_block;
		HSet<IOBlock> input_blocks;
		HSet<HId> contained_blocks;
		HSet<IOBlock> exit_blocks;
		HList<ControlStruct> child_struct;
		ControlStruct* parent_struct = nullptr;

		void print(int indent = 0) {
			printIndent(indent);
			switch (type) {
			case ControlStructType::TAIL:
				printf("TAIL");
				break;
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
			printf(" Head: %d\n", head_block);
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
	};

	struct SSATransformToC : public SSATransformer {

		Binary* binary;
		Function* function;
		HSet<HId> resolveIds;
		HSet<HId> resolveBBs;
		HIdList<CArgument> arguments;
		HIdList<UnifiedExprs> unifiedExprs;

		virtual bool doTransformation (Binary* binary, Function* function);

		UnifiedExprs* getUnifiedExpr(HId uId);

		void analyzeStructure(ControlStruct& controlStruct, HId start_block_id);
		bool analyzeLoop(ControlStruct* loopStruc);
		void analyzeLoopFor(HId bbId, HSet<HId>& visitedNodes, ControlStruct* loopStruc);
		void analyzeLoopBack(HId bbId, HSet<HId>& visitedNodes, ControlStruct* loopStruc);

		void printControlStruct(ControlStruct* controlStruct, std::set<HId> printed);

		void printBasicBlock(SSABB& bb);
		void printExpression(SSAExpression& expression);
		void resolveArgs(SSAExpression& expression, const char* delimiter = ", ");
		void resolveArgWithoutOffset(SSAArgument& arg);
		void resolveArg(SSAArgument& arg);
		void resolveMemArg(SSAArgument& arg, uint32_t size);
		void resolveExpression(SSAExpression& expression);
		bool shouldResolve(SSAExpression& expr);

		bool shouldResolve(HId id);
	};

}

#endif // SSATRANSFORMTOC_H
