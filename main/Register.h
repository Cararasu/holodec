#ifndef HREGISTER_H
#define HREGISTER_H


#include "HString.h"
#include "General.h"
#include "HIdList.h"

namespace holodec {

	enum RegTrackType {
		H_REG_TRACK_TRACKED = 0,
		H_REG_TRACK_VOLATILE
	};
	enum RegType {
		H_REG_OTHER = 0,
		H_REG_GPR,
		H_REG_ADDRESS,
		H_REG_FLOAT,
		H_REG_VEC,
		H_REG_STACKPTR,
		H_REG_INSTRPTR,
		H_REG_FLAGS,
		H_REG_CONTROL,
		H_REG_DEBUG,
		H_REG_SEGMENT
	};

	struct Register {
		HId id;
		HString name;
		RegType type;
		StringRef directParentRef;
		StringRef parentRef;
		size_t size;
		size_t offset;
		bool clearParentOnWrite;

		void print (int indent = 0);
	};
	extern Register invalidReg;

}

#endif // HREGISTER_H
