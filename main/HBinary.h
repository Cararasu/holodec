#ifndef H_BINAHY_H
#define H_BINAHY_H

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "HData.h"
#include "HGeneral.h"
#include "HSection.h"
#include "HFunction.h"

#include "HStringDatabase.h"

namespace holodec {

	struct HBinary {
		HData* data;
		
		HList<HId> entrypoints;
		HIdList<HSymbol> symbols;
		HIdGenerator gen_sections;
		HIdList<HSection> sections;
		HIdList<HFunction> functions;
		//which architecture
		//global string
		size_t bitbase;
		HString arch;

		HStringDatabase stringDB;

		HBinary (HString fileName);
		HBinary (HData* data);
		virtual ~HBinary();

		uint8_t* getVDataPtr (size_t addr) {
			for (HSection & section : sections) {
				if (section.pointsToSection (addr))
					return section.getPtr<uint8_t>(data, addr - section.vaddr);
			}
			return 0;
		}
		size_t getVDataSize (size_t addr) {
			for (HSection & section : sections) {
				if (section.pointsToSection (addr))
					return section.size - (addr - section.vaddr);
			}
			return 0;
		}
		HData* getData () {
			return data;
		}
		template<typename T>
		inline T getValue (size_t offset = 0) {
			return ( (T*) (data->data + offset)) [0];
		}

		HId addSection (HSection section);
		HSection* getSection (HString string);
		HSection* getSection (HId id);
		HId addSymbol (HSymbol symbol);
		HSymbol* getSymbol (HString string);
		HSymbol* getSymbol (HId id);
		HSymbol* findSymbol(size_t addr,const HSymbolType* type);
		HId addFunction (HFunction function);
		HFunction* getFunction (HString string);
		HFunction* getFunction (HId id);
		bool addEntrypoint (HId name);

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Printing HBinary %s\n", data->filename.cstr());
			printf ("Printing Sections\n");
			for (HSection & section : sections) {
				section.print (indent + 1);
			}
			printf ("Printing Symbols\n");
			for (HSymbol & symbol : symbols) {
				symbol.print (indent + 1);
				for (HId id : entrypoints) {
					if (id == symbol.id) {
						printIndent (indent + 2);
						printf ("Is EntryPoint\n");
					}
				}
			}
			printIndent (indent);
			printf ("Printing StringDB %s\n", data->filename.cstr());
			for (auto & entry : stringDB) {
				printIndent (indent + 1);
				printf ("%s: %s\n", entry.first.cstr(), entry.second.cstr());
			}
		}
	};

	HBinary * loadBinaryFromFile (const char* path);
	HBinary * loadBinaryFromMemory (uint8_t* memory, size_t size);

}

#endif // H_BINAHY_H
