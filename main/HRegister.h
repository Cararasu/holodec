#ifndef HREGISTER_H
#define HREGISTER_H

#include "HId.h"
#include "HString.h"
#include "HGeneral.h"

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
		HRegType type;
		HRegTrackType track;
		HId directParentId;
		HId parentId;
		HString name;
		size_t size;
		size_t offset;
		bool clearParentOnWrite;
		HList<HRegister> subregisters;

		HRegister() = default;
		HRegister (HString name, size_t size, size_t offset) : HRegister (name, size, offset, false) {};
		HRegister (HString name, size_t size, size_t offset, bool clearParentOnWrite) : HRegister (name, H_REG_OTHER, size, offset, clearParentOnWrite) {};

		HRegister (HString name, HRegType type, size_t size, size_t offset) : HRegister (name, type, H_REG_TRACK_TRACKED, size, offset) {};
		HRegister (HString name, HRegType type, HRegTrackType track, size_t size, size_t offset) : HRegister (name, type, track, size, offset, false) {};

		HRegister (HString name, HRegType type, size_t size, size_t offset, bool clearParentOnWrite) : HRegister (name, type, H_REG_TRACK_TRACKED, size, offset, clearParentOnWrite) {};
		HRegister (HString name, HRegType type, HRegTrackType track, size_t size, size_t offset, bool clearParentOnWrite) : id (0), type (type), track (track), parentId (0), name (name), size (size), offset (offset), clearParentOnWrite (clearParentOnWrite), subregisters (0) {};

		HRegister (HString name, size_t size, size_t offset, HList<HRegister> subregisters) : HRegister (name, size, offset, false, subregisters) {};
		HRegister (HString name, size_t size, size_t offset, bool clearParentOnWrite, HList<HRegister> subregisters) : HRegister (name, H_REG_OTHER, size, offset, clearParentOnWrite, subregisters) {};

		HRegister (HString name, HRegType type, size_t size, size_t offset, HList<HRegister> subregisters) : HRegister (name, type, H_REG_TRACK_TRACKED, size, offset, false, subregisters) {};
		HRegister (HString name, HRegType type, HRegTrackType track, size_t size, size_t offset, HList<HRegister> subregisters) : HRegister (name, type, track, size, offset, false, subregisters) {};
		HRegister (HString name, HRegType type, size_t size, size_t offset, bool clearParentOnWrite, HList<HRegister> subregisters) : HRegister (name, type, H_REG_TRACK_TRACKED, size, offset, clearParentOnWrite, subregisters) {};
		HRegister (HString name, HRegType type, HRegTrackType track, size_t size, size_t offset, bool clearParentOnWrite, HList<HRegister> subregisters) : id (0), type (type), track (track), directParentId(0), parentId(0), name (name), size (size), offset (offset), clearParentOnWrite (clearParentOnWrite), subregisters (subregisters) {};

		HRegister (const HRegister& reg) : id (0), type (reg.type), track (reg.track), directParentId(0), parentId(0), name (reg.name), size (reg.size), offset (reg.offset), clearParentOnWrite (reg.clearParentOnWrite), subregisters (reg.subregisters) {}
		HRegister (const HRegister&& reg) : id (0), type (reg.type), track (reg.track), directParentId(0), parentId(0), name (reg.name), size (reg.size), offset (reg.offset), clearParentOnWrite (reg.clearParentOnWrite), subregisters (reg.subregisters) {}

		HRegister* addRegister (HRegister* reg);
		HRegister* getRegister (const HString string);
		HRegister* getRegister (const HId id);
		void setParentId (HId parentId);
		void relabel (HIdGenerator* gen, std::function<void (HId, HId) > replacer = nullptr);
		void print (int indent = 0);
	};

	extern HRegister invalidReg;

}

#endif // HREGISTER_H
