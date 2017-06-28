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

		static const HSymbolType symbool;
		static const HSymbolType symint;
		static const HSymbolType symuint;
		static const HSymbolType symfloat;
		static const HSymbolType symstring;
		static const HSymbolType symfunc;
	};

	struct HSymbol {
		HId id;
		HString name;

		const HSymbolType* symboltype;
		HType* type;

		size_t vaddr;
		size_t paddr;
		size_t size;

		void print (int indent = 0);
	};
	struct HSection {
		HId id;
		//name of the section
		HString name;

		//the offset into the memory
		size_t offset;
		//the virtual address, that section is mapped to
		size_t vaddr;
		//size_t paddr;needed?
		//the size of the section
		size_t size;
		
		//read/write/executable
		uint32_t srwx;

		HList<HSection> subsections;

		HSection() = default;
		HSection (const HSection&) = default;
		HSection operator= (const HSection&& sec) {
			return HSection (sec);
		}

		HId addSection (HSection section);
		HSection* getSection (HId id);
		HSection* getSection (HString name);

		size_t pointsToSection (size_t addr) {
			return vaddr <= addr && addr < vaddr + size;
		}
		template<typename T>
		T* getPtr (HData* data, size_t offset) {
			return (T*)(data->data + this->offset + offset);
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
