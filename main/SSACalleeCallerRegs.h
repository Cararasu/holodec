#pragma once

#include "SSATransformer.h"

#include <set>

namespace holodec {

	struct CalleeArgument {
		HId ssaId = 0;
		uint32_t size = 0;
		int64_t change = 0;

		CalleeArgument() {}
		CalleeArgument(SSAArgument& arg) : ssaId(arg.ssaId) {}
		CalleeArgument(CalleeArgument& arg) : ssaId(arg.ssaId), size(arg.size), change(arg.change) {}
		CalleeArgument(const CalleeArgument&& arg) : ssaId(arg.ssaId), size(arg.size), change(arg.change) {}

		CalleeArgument& operator=(CalleeArgument arg) {
			ssaId = arg.ssaId;
			change = arg.change;
			size = arg.size;
			return *this;
		}

		CalleeArgument replace(CalleeArgument arg) {
			CalleeArgument retArg = arg;
			retArg.change += change;
			return retArg;
		}

		void print() {
			printf("SSA: %" PRId32 " + " PRId64 "[%" PRId32 "]\n", ssaId, change, size);
		}
	};
	inline bool operator==(CalleeArgument& lhs, CalleeArgument& rhs) {
		return lhs.ssaId == rhs.ssaId && lhs.change == rhs.change;
	}

	class SSACalleeCallerRegs : public SSATransformer {

		std::vector<StringRef> volatileRegs;
	public:
		SSACalleeCallerRegs() :volatileRegs() {}
		SSACalleeCallerRegs(std::vector<StringRef> volatileRegs) :volatileRegs(volatileRegs) {}

		virtual bool doTransformation(Binary* binary, Function* function);
	private:
		std::set<Function*> visitedFuncs;

		bool isOnlyRecursive(Function* function, HId currentId, HId lastId, std::set<HId>& exprvisited, Reference locref);

	};

}