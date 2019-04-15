#pragma once

#include "File.h"
#include "DataSource.h"

namespace holodec {


	struct File {
		String name;
		size_t size;
		void* data;
	};

	struct MemorySpace {
		u32 id;
		String name;
		DynArray<DataSegment> dataSegments;
		uint64_t wordsize = 1;
		Endianess endianess = Endianess::eLittle;

		bool is_mapped(uint64_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.is_mapped(addr)) {
					return true;
				}
			}
			return false;
		}
		u64 mapped_size(uint64_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				u64 bytes_left = dataSegment.bytes_left(addr);
				if (bytes_left) return bytes_left;
			}
			return 0;
		}
		DataSegment* getDataSegment(size_t addr) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.is_mapped(addr)) {
					return &dataSegment;
				}
			}
			return nullptr;
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

	};

}