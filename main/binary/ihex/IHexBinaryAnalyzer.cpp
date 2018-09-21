
#include "IHexBinaryAnalyzer.h"
#include "../../Function.h"
#include "../../Main.h"
#include "../../Data.h"

#include <assert.h>

namespace holoihex {

	uint8_t charToInt(uint8_t c) {
		if (c >= '0' && c <= '9')
			return c - '0';
		else if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;
		else
			assert(false);
		return -1;
	}
	inline uint8_t parse8BitHex (holodec::File* file, size_t index) {
		return charToInt(file->data[index]) << 4 | charToInt(file->data[index + 1]);
	}
	inline uint16_t parse16BitHex (holodec::File* file, size_t index) {
		return static_cast<uint16_t>(parse8BitHex(file, index)) << 8 | static_cast<uint16_t>(parse8BitHex(file, index + 2));
	}
	inline uint32_t parse32BitHex (holodec::File* file, size_t index) {
		return static_cast<uint32_t>(parse16BitHex(file, index)) << 16 | static_cast<uint32_t>(parse16BitHex(file, index + 4));
	}

	bool IHexBinaryAnalyzer::canAnalyze(holodec::File* file) {
		if (file->data[0] == ':') {
			return true;
		}
		return false;
	}

	bool IHexBinaryAnalyzer::init(holodec::File* file) {
		if (!file)
			return false;

		binary = new holodec::Binary(file->name);
		binary->bitbase = 8;
		binary->bytebase = 1;
		binary->endianess = holodec::Endianess::eLittle;

		holodec::MemorySpace* memSpace = new holodec::MemorySpace();
		memSpace->endianess = holodec::Endianess::eLittle;
		memSpace->wordsize = 1;

		bool reachedfinal = false;
		uint64_t index = 0;
		while (index < file->data.size() && !reachedfinal) {
			uint64_t size = parse8BitHex(file, index + 1);
			uint64_t offset = parse16BitHex(file, index + 3);
			uint64_t type = parse8BitHex(file, index + 7);
			switch (type) {
			case 0x00: {
				holodec::DataSegment* appendSegment = nullptr;
				for (holodec::DataSegment* dataSegment : memSpace->dataSegments) {
					if (dataSegment->offset + dataSegment->data.size() == offset) {
						appendSegment = dataSegment;
						break;
					}
				}
				if (!appendSegment) {
					memSpace->dataSegments.push_back(new holodec::DataSegment());
					appendSegment = memSpace->dataSegments.back();
					appendSegment->data.resize(size);
					appendSegment->offset = offset;
				}
				else {
					appendSegment->data.resize(appendSegment->data.size() + size);
				}

				index += 0x9;
				for (int i = 0; i < size; i++) {
					appendSegment->data[offset + i - appendSegment->offset] = parse8BitHex(file, index);
					index += 0x02;
				}
				index += 0x02;
			} break;
			case 0x01: {
				holodec::DataSegment* data = new holodec::DataSegment();
				binary = new holodec::Binary(file->name);

				binary->arch = holodec::Main::g_main->getArchitecture("avr");

				binary->defaultMemSpace = memSpace;

				holodec::Memory* mem = binary->arch->getMemory("pmem");
				assert(mem);
				binary->memorySpaces.emplace(mem->id, memSpace);

				holodec::Symbol* sym = binary->findSymbol(0, &holodec::SymbolType::symfunc);
				if (!sym) {
					sym = new holodec::Symbol();
					sym->name = "entry";
					sym->size = 0;
					sym->symboltype = &holodec::SymbolType::symfunc;
					sym->vaddr = 0x68;
					binary->addSymbol(sym);
				}
				binary->addEntrypoint(sym->id);
				return true;
			}
			case 0x02:
				//ignore
				assert(false);
				break;
			case 0x03:
				//ignore
				assert(false);
				break;
			case 0x04:
				//ignore
				assert(false);
				break;
			case 0x05:
				//ignore
				assert(false);
				break;

			}
			if (reachedfinal)
				break;
			while (index < file->data.size() && file->data[index] != ':') index++;
		}
		return false;
	}
	bool IHexBinaryAnalyzer::terminate() {
		return true;
	}

}
