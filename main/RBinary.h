#ifndef R_BINARY_H
#define R_BINARY_H

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "RData.h"
#include "RGeneral.h"
#include "RSection.h"
#include "RFunction.h"

namespace holodec {

	struct RBinary {
		RData* data;
		RList<RSymbol*> entrypoints;
		RList<RSection> sections;
		RList<RFunction> functions;
		RString arch;
		
		RBinary (RString fileName);
		RBinary (RData* data);
		virtual ~RBinary();

		uint8_t* getVDataPtr (size_t addr) {
			for (RSection & section : sections) {
				size_t offset = section.getDataOffsetFromVAddr (addr);
				if (offset) return data->data + offset;
			}
			return 0;
		}
		size_t getVDataSize (size_t addr) {
			for (RSection & section : sections) {
				size_t offset = section.getDataOffsetFromVAddr (addr);
				if (offset) return section.size - (offset - section.vaddr);
			}
			return 0;
		}

		RSection* addSection (RSection* section);
		RSymbol* addSymbol (RSymbol* symbol);
		RFunction* addFunction (RFunction* function);
		bool addEntrypoint (RSymbol* entrypoint);

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Printing RBinary %s\n", data->filename);
			for (RSection & section : sections) {
				section.print (indent + 1);
			}
		}
	};

	RBinary * loadBinaryFromFile (const char* path);
	RBinary * loadBinaryFromMemory (uint8_t* memory, size_t size);

}

#endif // R_BINARY_H
