#ifndef H_SECTION_H
#define H_SECTION_H

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "HFunction.h"
#include "HClass.h"
#include "HData.h"
#include "HIdGenerator.h"

namespace holodec {

	struct HType;

	struct HSymbolType {
		HString name;

		static HSymbolType symbool;
		static HSymbolType symint;
		static HSymbolType symuint;
		static HSymbolType symfloat;
		static HSymbolType symstring;
		static HSymbolType symfunc;
	};

	struct HSymbol {
		HId id;
		HString name;

		HSymbolType symboltype;
		HType* type;

		size_t vaddr;
		size_t paddr;
		size_t size;

		void print (int indent = 0);
	};
	struct HSection {
		HId id;
		HString name;

		size_t offset;
		size_t vaddr;
		size_t paddr;
		size_t size;

		uint32_t srwx;

		HList<HSection> subsections;

		HId addSection (HSection section);
		HSection* getSection (HId id);
		HSection* getSection (HString name);

		HSection() = default;
		HSection (const HSection&) = default;
		HSection operator= (const HSection&& sec) {
			return HSection (sec);
		}

		size_t vAddrInSection (size_t addr) {
			if (vaddr <= addr && vaddr + size > addr)
				return true;
			return false;
		}
		size_t getDataOffsetFromVAddr (size_t addr) {
			return offset + addr - vaddr;
		}
		size_t getDataOffsetFromPAddr (size_t addr) {
			return offset + addr - paddr;
		}

		template<typename T>
		inline T getValue (HData* data, size_t offset = 0) {
			return ( (T*) (data->data + this->offset + offset)) [0];
		}
		
		void print (int indent = 0) {
			printIndent (indent);
			printf ("Section %s \t%x-%x\n", name.cstr(), vaddr, vaddr + size);
			printIndent (indent);
			printf ("Offset: %x Flags: %s %s %s\n", offset, srwx & 0x1 ? "H" : " ", srwx & 0x2 ? "W" : " ", srwx & 0x4 ? "X" : " ");
			for (HSection & section : subsections) {
				section.print (indent + 1);
			}
		}
	};
}

#endif // H_SECTION_H
