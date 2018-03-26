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

		IOBlock(HId blockId) : blockId(blockId), count(0){}
	};
	inline bool operator<(const IOBlock& lhs, const IOBlock& rhs) {
		return lhs.blockId < rhs.blockId;
	}
	inline bool operator==(const IOBlock& lhs, const IOBlock& rhs) {
		return lhs.blockId == rhs.blockId;
	}

	struct ControlStruct {
		const ControlStructType type;
		HSet<IOBlock> input_blocks;
		HSet<HId> contained_blocks;
		HSet<IOBlock> exit_blocks;
		HList<ControlStruct> child_struct;
		ControlStruct* parent_struct = nullptr;

		ControlStruct(ControlStructType type) : type(type) {}

		void print(int indent = 0) {
			printIndent(indent);
			switch (type) {
			case ControlStructType::TAIL:
				printf("Tail\n");
				break;
			case ControlStructType::SEQUENCE:
				printf("SEQUENCE\n");
				break;
			case ControlStructType::BRANCH:
				printf("BRANCH\n");
				break;
			case ControlStructType::LOOP:
				printf("LOOP\n");
				break;
			case ControlStructType::GLOBAL:
				printf("GLOBAL\n");
				break;
			}
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
		bool analyzeLoop(HId bbId, ControlStruct* loopStruc);
		bool analyzeLoop(HId bbId, HMap<HId, bool>& visitedBlocks, ControlStruct* loopStruc);
		void analyzeOutputBranch(HId bbId, HSet<std::pair<HId, HId>>& forwardEdges);

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
