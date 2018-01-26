#ifndef HREGISTER_H
#define HREGISTER_H


#include "HString.h"
#include "General.h"
#include "HIdList.h"
#include "CHolodecHeader.h"

namespace holodec {

	enum class RegTrackType {
		eTracked = REG_TRACK_TRACKED,
		eVolatile = REG_TRACK_VOLATILE
	};
	enum class RegType {
		eOther = REG_OTHER,
		eGPR = REG_GPR,
		eAddress = REG_ADDRESS,
		eFloat = REG_FLOAT,
		eVec = REG_VEC,
		eStackPtr = REG_STACKPTR,
		eInstrPtr = REG_INSTRPTR,
		eFlag = REG_FLAG,
		eControl = REG_CONTROL,
		eDebug = REG_DEBUG,
		eSegment = REG_SEGMENT
	};

	struct Register {
		HId id;
		HString name;
		RegType type;
		StringRef directParentRef;
		StringRef parentRef;
		uint32_t size;
		uint32_t offset;
		bool clearParentOnWrite;

		void print (int indent = 0);
	};
	extern Register invalidReg;

}

#endif // HREGISTER_H
