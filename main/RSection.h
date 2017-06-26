#ifndef R_SECTION_H
#define R_SECTION_H

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "RFunction.h"
#include "RClass.h"

namespace holodec {

	struct RType;
	
	struct RSymbolType{
		RString name;
		
		static RSymbolType symbool;
		static RSymbolType symint;
		static RSymbolType symuint;
		static RSymbolType symfloat;
		static RSymbolType symstring;
		static RSymbolType symfunc;
	};
	
	struct RSymbol {
		RString name;

		RSymbolType symboltype;
		RType* type;

		size_t vaddr;
		size_t paddr;
		size_t size;

		void print (int indent = 0);
	};
	struct RSection {
		RString name;

		size_t offset;
		size_t vaddr;
		size_t paddr;
		size_t size;

		uint32_t srwx;

		RList<RSymbol> symbols;
		RList<RSection> subsections;

		RSection* addSection (RSection* section);
		RSymbol* addSymbol (RSymbol* symbol);

		RSection() = default;
		RSection(const RSection&) = default;
		RSection operator= (const RSection&& sec){
			return RSection(sec);
		}

		size_t getDataOffsetFromVAddr (size_t addr) {
			if (vaddr <= addr && vaddr + size > addr)
				return addr - vaddr;
			return 0;
		}
		size_t getDataOffsetFromPAddr (size_t addr) {
			if (paddr <= addr && paddr + size > addr)
				return addr - paddr;
			return 0;
		}

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Section %s \t%x-%x\n", name.cstr(), vaddr, vaddr + size);
			printIndent (indent);
			printf ("Offset: %x Flags: %s %s %s\n", offset, srwx & 0x1 ? "R" : " ", srwx & 0x2 ? "W" : " ", srwx & 0x4 ? "X" : " ");
			for (RSection & section : subsections) {
				section.print (indent + 1);
			}
			for (RSymbol & symbol : symbols) {
				symbol.print (indent + 1);
			}
		}
	};
}

#endif // R_SECTION_H
