#pragma once

#include "SSATransformer.h"

#include <set>

namespace holodec {

	struct CalleeArgument {
		HId ssaId = 0;
		int64_t valueoffset = 0;
		uint32_t offset = 0, size = 0;

		CalleeArgument() {}
		CalleeArgument(SSAArgument& arg) : ssaId(arg.ssaId), valueoffset(arg.valueoffset), offset(arg.offset), size(arg.size) {}
		CalleeArgument(CalleeArgument& arg) : ssaId(arg.ssaId), valueoffset(arg.valueoffset), offset(arg.offset), size(arg.size) {}
		CalleeArgument(const CalleeArgument&& arg) : ssaId(arg.ssaId), valueoffset(arg.valueoffset), offset(arg.offset), size(arg.size) {}

		CalleeArgument& operator=(CalleeArgument arg) {
			ssaId = arg.ssaId;
			valueoffset = arg.valueoffset;
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
			return arg.type == SSAArgType::eId && ssaId == arg.ssaId && valueoffset == arg.valueoffset;
		}
		void print() {
			printf("SSA: %" PRId32 " + %" PRId64 " [%" PRId32 ",%" PRId32 "]\n", ssaId, valueoffset, offset, size);
		}
	};
	inline bool operator==(CalleeArgument& lhs, CalleeArgument& rhs) {
		return lhs.ssaId == rhs.ssaId && lhs.valueoffset == rhs.valueoffset;
	}

	class SSACalleeCallerRegs : public SSATransformer {

		SSARepresentation* ssaRep;

		bool isInput(CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, CalleeArgument* retArg);

		bool isInputMem(HId memId, CalleeArgument arg, uint32_t outoffset, std::set<HId>& exprvisited, CalleeArgument* retArg, CalleeArgument ptrArg);

		virtual bool doTransformation(Binary* binary, Function* function);

	};

}