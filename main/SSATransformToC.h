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
		HId id = 0;
		HId ssaId = 0;
		Reference ref;
		std::set<HId> phiIds;
		std::set<HId> occuringIds;
	};
	enum class ControlStructType{
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
		HId head_block = 0;
		HId main_exit = 0;
		HSet<IOBlock> input_blocks;
		HSet<HId> contained_blocks;
		HSet<IOBlock> exit_blocks;
		HList<ControlStruct> child_struct;
		ControlStruct* parent_struct = nullptr;

		void print(int indent = 0);
	};

	struct SSATransformToC : public SSATransformer {

		Binary* binary;
		Function* function;
		HMap<HId, HId> argumentIds;
		HSet<HId> resolveIds;
		HSet<HId> resolveBBs;
		HIdList<CArgument> arguments;
		HIdList<UnifiedExprs> unifiedExprs;

		virtual bool doTransformation (Binary* binary, Function* function);
		UnifiedExprs* getPhiUnifiedExpr(HId id);
		UnifiedExprs* getUnifiedExpr(HId id);
		UnifiedExprs* getUnifiedExpr(Reference ref);

		void analyzeStructure(ControlStruct& controlStruct, HId start_block_id);
		bool analyzeLoop(ControlStruct* loopStruc);
		void analyzeLoopFor(HId bbId, HSet<HId>& visitedNodes, ControlStruct* loopStruc);
		void analyzeLoopBack(HId bbId, HSet<HId>& visitedNodes, ControlStruct* loopStruc);
		void consolidateBranchLoops(ControlStruct* controlStruct);


		void resolveBlockArgument(ControlStruct* controlStruct, SSAArgument arg, std::set<HId>& printed, uint32_t indent = 0);
		void resolveBranchExpr(ControlStruct* controlStruct, std::set<HId>& printed, uint32_t indent = 0);
		void resolveBlock(ControlStruct* controlStruct, SSABB& bb, std::set<HId>& printed, uint32_t indent = 0);
		void printControlStruct(ControlStruct* controlStruct, SSABB& bb, std::set<HId>& printed, uint32_t indent = 0);

		bool printExpression(SSAExpression& expression, uint32_t indent);
		bool resolveArgVariable(SSAExpression& expr, bool write);
		void resolveArgs(SSAExpression& expression, const char* delimiter = ", ");
		void resolveArg(SSAArgument arg);
		bool resolveExpression(SSAExpression& expression);
		bool shouldResolve(SSAExpression& expr);

		bool shouldResolve(HId id);
	};

}

#endif // SSATRANSFORMTOC_H
