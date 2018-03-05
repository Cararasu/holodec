#ifndef H_SECTION_H
#define H_SECTION_H

#include "General.h"
#include <stdio.h>
#include <vector>
#include "Function.h"
#include "Class.h"
#include "Data.h"


namespace holodec {

	struct Type;

	struct SymbolType {
		HString name;

		static const SymbolType symbool;
		static const SymbolType symint;
		static const SymbolType symuint;
		static const SymbolType symfloat;
		static const SymbolType symstring;
		static const SymbolType symfunc;
		static const SymbolType symdynfunc;
	};

	struct Symbol {
		HId id;
		HString name;

		const SymbolType* symboltype;
		HId typeId;

		size_t vaddr;
		size_t size;

		void print (int indent = 0);
	};
	struct Section {
		HId id;
		//name of the section
		HString name;

		//the offset into the memory
		size_t offset;
		//the virtual address, that section is mapped to
		size_t vaddr;
		//the size of the section
		size_t size;
		
		//read/write/executable
		uint32_t srwx;

		HList<Section*> subsections;

		Section() = default;
		Section (const Section&) = default;
		Section operator= (const Section&& sec) {
			return Section (sec);
		}

		HId addSection (Section* section);
		Section* getSection (HId id);
		Section* getSection (HString name);

		size_t pointsToSection (size_t addr) {
			return vaddr <= addr && addr < vaddr + size;
		}
		
		void print (int indent = 0) {
			printIndent (indent);
			printf ("Section %s \t0x%" PRIx64 "-0x%" PRIx64 "\n", name.cstr(), vaddr, vaddr + size);
			printIndent (indent);
			printf ("Offset: 0x%" PRIx64 " Flags: %s %s %s\n", offset, srwx & 0x1 ? "R" : " ", srwx & 0x2 ? "W" : " ", srwx & 0x4 ? "X" : " ");
			for (Section* section : subsections) {
				section->print (indent + 1);
			}
		}
	};
}

#endif // H_SECTION_H
