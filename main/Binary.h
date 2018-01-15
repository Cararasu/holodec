#ifndef H_BINAHY_H
#define H_BINAHY_H

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "Data.h"
#include "General.h"
#include "Section.h"
#include "Function.h"

#include "HStringDatabase.h"

namespace holodec {

	struct Binary {
		Data* data;

		HList<HId> entrypoints;
		HIdPtrList<Symbol*> symbols;
		HIdPtrList<Section*> sections;
		HIdPtrList<Function*> functions;
		//which architecture
		//global string
		size_t bitbase;
		HString arch;

		HStringDatabase stringDB;

		Binary (HString fileName);
		Binary (Data* data);
		virtual ~Binary();

		uint8_t* getVDataPtr (size_t addr) {
			for (Section* section : sections) {
				if (section->pointsToSection (addr))
					return section->getPtr<uint8_t> (data, addr - section->vaddr);
			}
			return 0;
		}
		size_t getVDataSize (size_t addr) {
			for (Section* section : sections) {
				if (section->pointsToSection (addr))
					return section->size - (addr - section->vaddr);
			}
			return 0;
		}
		Data* getData () {
			return data;
		}
		template<typename T>
		inline T getValue (size_t offset = 0) {
			return ( (T*) (data->data + offset)) [0];
		}

		HId addSection (Section* section);
		Section* getSection (HString string);
		Section* getSection (HId id);

		HId addSymbol (Symbol* symbol);
		Symbol* getSymbol (HString string);
		Symbol* getSymbol (HId id);
		Symbol* findSymbol (size_t addr, const SymbolType* type);

		HId addFunction (Function* function);
		Function* getFunction (HString string);
		Function* getFunction (HId id);

		bool addEntrypoint (HId name);

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Printing Binary %s\n", data->filename.cstr());
			printf ("Printing Sections\n");
			for (Section* section : sections) {
				section->print (indent + 1);
			}
			printf ("Printing Symbols\n");
			for (Symbol* symbol : symbols) {
				symbol->print (indent + 1);
				for (HId id : entrypoints) {
					if (id == symbol->id) {
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

	Binary * loadBinaryFromFile (const char* path);
	Binary * loadBinaryFromMemory (uint8_t* memory, size_t size);

}

#endif // H_BINAHY_H
