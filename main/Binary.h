#ifndef H_BINAHY_H
#define H_BINAHY_H

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <assert.h>
#include "Data.h"
#include "General.h"
#include "Section.h"
#include "Function.h"
#include "Architecture.h"

#include "HStringDatabase.h"
#include "DynamicLibrary.h"

namespace holodec {

	struct MemoryArea {
		StringRef name;
		HList<DataSegment*> dataSegments;
		uint64_t wordsize = 1;
		Endianess endianess = Endianess::eBig;

		bool isMapped(uint64_t addr) {
			for (DataSegment* dataSegment : dataSegments) {
				if (dataSegment->isInSegment(addr, wordsize)) {
					return true;
				}
			}
			return false;
		}
		uint64_t mappedSize(uint64_t addr) {
			for (DataSegment* dataSegment : dataSegments) {
				if (dataSegment->isInSegment(addr, wordsize)) {
					return addr - dataSegment->offset;
				}
			}
			return 0;
		}
		void copyData(uint8_t* buffer, uint64_t addr, uint64_t size) {
			for (DataSegment* dataSegment : dataSegments) {
				if (dataSegment->isInSegment(addr, wordsize)) {
					return dataSegment->copyData(buffer, addr, size, wordsize);
				}
			}
		}
		const uint8_t* getVDataPtr(size_t addr) {
			for (DataSegment* dataSegment : dataSegments) {
				if (dataSegment->isInSegment(addr, wordsize)) {
					return dataSegment->getPtr(addr, wordsize);
				}
			}
			return nullptr;
		}
		const uint64_t getVData(size_t addr) {
			for (DataSegment* dataSegment : dataSegments) {
				if (dataSegment->isInSegment(addr, wordsize)) {
					return dataSegment->get(addr, wordsize, endianess);
				}
			}
			return 0;
		}
		DataSegment* getDataSegment(size_t addr) {
			for (DataSegment* dataSegment : dataSegments) {
				if (dataSegment->isInSegment(addr, wordsize)) {
					return dataSegment;
				}
			}
			return 0;
		}
	};
	struct Binary {
		HString name;
		MemoryArea* defaultArea;

		HList<HId> entrypoints;
		HIdPtrList<Function*> functions;
		HIdPtrList<DynamicLibrary*> dynamic_libraries;

		HIdPtrList<Symbol*> symbols;
		HIdPtrList<Section*> sections;

		HMap<HId, MemoryArea*> memoryAreas;

		size_t bitbase;
		Endianess endianess;
		Architecture* arch;

		Binary(HString name);
		virtual ~Binary();

		const uint8_t* getVDataPtr(size_t addr) {
			return defaultArea->getVDataPtr(addr);
		}
		const uint8_t* getVDataPtr(HId memorySegmentId, size_t addr) {
			for (std::pair<HId, MemoryArea*> entry : memoryAreas) {
				if (entry.first == memorySegmentId) {
					return entry.second->getVDataPtr(addr);
				}
			}
			return nullptr;
		}
		const uint64_t getVData(size_t addr, size_t bytesize = 1) {
			assert(bytesize > 0 && bytesize <= sizeof(uint64_t));
			return defaultArea->getVData(addr);
		}
		const uint64_t getVData(HId memorySegmentId, size_t addr) {
			memoryAreas.at(memorySegmentId);
			for (std::pair<HId, MemoryArea*> entry : memoryAreas) {
				if (entry.first == memorySegmentId) {
					return entry.second->getVData(addr);
				}
			}
			return 0;
		}
		DataSegment* getDataSegment(size_t addr) {
			return defaultArea->getDataSegment(addr);
		}
		DataSegment* getDataSegment(HId memorySegmentId, size_t addr) {
			for (std::pair<HId, MemoryArea*> entry : memoryAreas) {
				if (entry.first == memorySegmentId) {
					return entry.second->getDataSegment(addr);
				}
			}
			return 0;
		}/*
		template<typename T>
		inline const uint64_t getValue(size_t offset = 0) {
			return *reinterpret_cast<const T*>(defaultArea->get(offset));
		}
		template<typename T>
		inline const T* getPtr(size_t offset = 0) {
			return reinterpret_cast<const T*>(defaultArea->get(offset));
		}
		template<typename T>
		inline const T& getValue(HString& memorySpace, size_t offset = 0) {
			this->arch->get
			return *reinterpret_cast<const T*>(defaultArea->get(offset));
		}
		template<typename T>
		inline const T* getPtr(HString& memorySpace, size_t offset = 0) {
			return reinterpret_cast<const T*>(defaultArea->get(offset));
		}
		template<typename T>
		inline const T& getValue(HId memorySpaceId, size_t offset = 0) {
			//this->arch->
			return *reinterpret_cast<const T*>(defaultArea->get(offset));
		}
		template<typename T>
		inline const T* getPtr(HId memorySpaceId, size_t offset = 0) {
			return reinterpret_cast<const T*>(defaultArea->get(offset));
		}*/

		Memory* getMemory(HString string);
		Memory* getMemory(HId id);

		HId addSection(Section* section);
		Section* getSection(HString string);
		Section* getSection(HId id);

		HId addSymbol (Symbol* symbol);
		Symbol* getSymbol (HString string);
		Symbol* getSymbol (HId id);
		Symbol* findSymbol (size_t addr, const SymbolType* type);

		HId addFunction (Function* function);
		Function* getFunction (HString string);
		Function* getFunction (HId id);
		Function* getFunctionByAddr(uint64_t addr);

		HId addDynamicLibrary (DynamicLibrary* dynamicLibrary);
		DynamicLibrary* getDynamicLibrary (HString string);
		DynamicLibrary* getDynamicLibrary (HId id);

		bool addEntrypoint (HId name);

		void print (int indent = 0) {
			printIndent (indent);
			printf ("Printing Binary %s\n", name.cstr());
			printIndent(indent);
			printf("Printing Mapped Memories\n");
			for (std::pair<HId, MemoryArea*> area : memoryAreas) {
				printIndent(indent + 1);
				printf("Memory-Area %s\n", arch->getMemory(area.first)->name.cstr());
				for (DataSegment* segment : area.second->dataSegments) {
					printIndent(indent + 2);
					printf("Block: 0x%" PRIx64 " - 0x%" PRIx64 "\n", segment->offset, segment->offset + (segment->data.size() / area.second->wordsize));
					printIndent(indent + 2);
					printf("Size: 0x%zx\n", segment->data.size());
				}
			}
			printIndent(indent);
			printf("Printing Sections\n");
			for (Section* section : sections) {
				section->print (indent + 1);
			}
			printIndent (indent);
			printf ("Printing Dynamic Libraries\n");
			for (DynamicLibrary* dynlib : dynamic_libraries) {
				printIndent (indent + 1);
				printf("%s\n", dynlib->name.cstr());
			}
			printIndent (indent);
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
		}
	};

	Binary * loadBinaryFromFile (const char* path);
	Binary * loadBinaryFromMemory (uint8_t* memory, size_t size);

}

#endif // H_BINAHY_H
