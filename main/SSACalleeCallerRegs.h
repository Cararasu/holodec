#pragma once

#include "SSATransformer.h"

#include <set>

namespace holodec {

	struct CalleeArgument {
		HId ssaId = 0;
		int64_t change = 0;

		CalleeArgument() {}
		CalleeArgument(SSAArgument& arg) : ssaId(arg.ssaId) {}
		CalleeArgument(const CalleeArgument& arg) : ssaId(arg.ssaId), change(arg.change) {}
		CalleeArgument(const CalleeArgument&& arg) : ssaId(arg.ssaId), change(arg.change) {}

		CalleeArgument& operator=(CalleeArgument arg) {
			ssaId = arg.ssaId;
			change = arg.change;
			return *this;
		}

		CalleeArgument replace(CalleeArgument arg) {
			CalleeArgument retArg = arg;
			retArg.change += change;
			return retArg;
		}

		void print() {
			printf("SSA: %" PRId32 " + %" PRId64 "\n", ssaId, change);
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

		bool isOnlyRecursive(Function* function, HId currentId, HId lastId, std::set<HId>& exprvisited, Reference locref);

	};

}