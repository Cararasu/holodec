#pragma once

#include "SSATransformer.h"

#include <set>

namespace holodec {

	struct CalleeArgument {
		HId ssaId = 0;
		uint32_t offset = 0, size = 0;

		CalleeArgument() {}
		CalleeArgument(SSAArgument& arg) : ssaId(arg.ssaId) {}
		CalleeArgument(CalleeArgument& arg) : ssaId(arg.ssaId), offset(arg.offset), size(arg.size) {}
		CalleeArgument(const CalleeArgument&& arg) : ssaId(arg.ssaId), offset(arg.offset), size(arg.size) {}

		CalleeArgument& operator=(CalleeArgument arg) {
			ssaId = arg.ssaId;
			offset = arg.offset;
			size = arg.size;
			return *this;
		}

		CalleeArgument replace(CalleeArgument arg) {
			CalleeArgument retArg = arg;
			retArg.offset += offset;
			return retArg;
		}

		bool equals(SSAArgument& arg) {
			return arg.type == SSAArgType::eId && ssaId == arg.ssaId;
		}
		void print() {
			printf("SSA: %" PRId32 "[%" PRId32 ",%" PRId32 "]\n", ssaId, offset, size);
		}
	};
	inline bool operator==(CalleeArgument& lhs, CalleeArgument& rhs) {
		return lhs.ssaId == rhs.ssaId;
	}

	class SSACalleeCallerRegs : public SSATransformer {

		std::vector<StringRef> volatileRegs;
	public:
		SSACalleeCallerRegs() :volatileRegs() {}
		SSACalleeCallerRegs(std::vector<StringRef> volatileRegs) :volatileRegs(volatileRegs) {}

		virtual bool doTransformation(Binary* binary, Function* function);
	private:
		std::set<Function*> visitedFuncs;

		bool isInput(Function* function, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, Register* reg, CalleeArgument* retArg);
		bool isInputMem(Function* function, HId memId, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, Register* reg, CalleeArgument* retArg, CalleeArgument ptrArg);

		bool isOnlyRecursive(Function* function, HId currentId, HId lastId, std::set<HId>& exprvisited, SSALocation location, Reference locref);

	};

}