#pragma once

#include "File.h"

namespace holodec {


	struct File {
		String name;
		size_t size;
		void* data;
	};

	struct DataSegment {
		String name;
		size_t offset;
		size_t size;
		void* data;

		void* getPtr(size_t index, size_t wordsize = 1) {
			size_t ptrindex = (index - offset) * wordsize;
			if (0 <= ptrindex && ptrindex < size) {
				return reinterpret_cast<void*>(reinterpret_cast<size_t>(data) + ptrindex);
			}
			return nullptr;
		}
	};

	struct MemorySpace {
		u32 id;
		String name;
		DynArray<DataSegment> dataSegments;
		uint64_t wordsize = 1;
		Endianess endianess = Endianess::eBig;

		bool isMapped(uint64_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.getPtr(addr, wordsize)) {
					return true;
				}
			}
			return false;
		}
		uint64_t mappedSize(uint64_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.getPtr(addr, wordsize)) {
					return dataSegment.size - (addr - dataSegment.offset);
				}
			}
			return 0;
		}
		const void* getVDataPtr(size_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.getPtr(addr, wordsize)) {
					return dataSegment.getPtr(addr, wordsize);
				}
			}
			return nullptr;
		}
		DataSegment* getDataSegment(size_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.getPtr(addr, wordsize)) {
					return &dataSegment;
				}
			}
			return 0;
		}
	};
	struct Section {
		u32 id;
		//name of the section
		String name;

		//the offset into the memory
		size_t offset;
		//the virtual address, that section is mapped to
		size_t vaddr;
		//the size of the section
		size_t size;

		//read/write/executable
		uint32_t srwx;

		DynArray<u32> subsections;

		Section() = default;
		Section(const Section&) = default;
		Section operator= (const Section&& sec) {
			return Section(sec);
		}

		size_t pointsToSection(size_t addr) {
			return vaddr <= addr && addr < vaddr + size;
		}
	};

	struct Binary {
		String name;
		u32 default_mem_space_id = 0;

		IdArray<MemorySpace> memorySpaces;

		Endianess endianess;

		IdArray<Section> sections;

		u32 addSection(Section* section);
		Section* getSection(u32 id);
		Section* getSection(String& name);


		//disassembled basic blocks

		//functions

		const void* getVDataPtr(size_t addr) {
			return memorySpaces[default_mem_space_id].getVDataPtr(addr);
		}
		const void* getVDataPtr(u32 memorySegmentId, size_t addr) {
			MemorySpace* memspace = &memorySpaces[memorySegmentId];
			return memspace ? memspace->getVDataPtr(addr) : nullptr;
		}
		DataSegment* getDataSegment(size_t addr) {
			return memorySpaces[default_mem_space_id].getDataSegment(addr);
		}
		DataSegment* getDataSegment(u32 memorySegmentId, size_t addr) {
			MemorySpace* memspace = &memorySpaces[memorySegmentId];
			return memspace ? memspace->getDataSegment(addr) : nullptr;
		}

	};

}