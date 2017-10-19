#ifndef HREGISTER_H
#define HREGISTER_H


#include "HString.h"
#include "HGeneral.h"
#include "HIdList.h"

namespace holodec {

	enum HRegTrackType {
		H_REG_TRACK_TRACKED = 0,
		H_REG_TRACK_VOLATILE
	};
	enum HRegType {
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

	struct HRegister {
		HId id;
		HString name;
		HRegType type;
		HStringRef directParentRef;
		HStringRef parentRef;
		size_t size;
		size_t offset;
		bool clearParentOnWrite;

		void print (int indent = 0);
	};
	extern HRegister invalidReg;

}

#endif // HREGISTER_H
