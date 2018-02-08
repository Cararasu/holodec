#pragma once

#include <stdint.h>
#include "General.h"

namespace holodec {

	struct File {
		HString name;
		HList<uint8_t> data;

		File(HString name, HList<uint8_t> data) : name(name), data(data) {}
	};

	struct DataSegment {
		HString name;
		uint64_t offset;
		HList<uint8_t> data;

		DataSegment() {}
		DataSegment(DataSegment* data);
		DataSegment(DataSegment& file) = default;
		DataSegment(DataSegment && file) = default;
		~DataSegment() = default;

		uint64_t size() {
			return data.size();
		}
		void copyData(uint8_t* buffer, uint64_t index, uint64_t size, uint64_t wordsize) {
			size_t multIndex = (index - offset) * wordsize;
			memcpy(buffer, data.data() + multIndex, size);
		}

		const bool isInSegment(size_t index, uint64_t wordsize) {
			size_t multIndex = (index - offset) * wordsize;
			return 0 <= multIndex && multIndex < data.size();
		}

		uint64_t get(size_t index, uint64_t wordsize, Endianess endianess) {
			size_t multIndex = (index - offset) * wordsize;
			if (0 <= multIndex && multIndex < data.size()) {
				uint64_t value = 0;
				switch (endianess) {
				case Endianess::eBig: {
					for (int i = 0; i < wordsize; i++) {
						value = (value << 8) | data[multIndex + i];
					}
				}break;
				case Endianess::eLittle:{
					for (int i = wordsize - 1; i >= 0; i--) {
						value = (value << 8) | data[multIndex + i];
					}
				}break;
				}
				return value;
			}
			return 0x00;
		}
		uint8_t* getPtr(size_t index, uint64_t wordsize) {
			size_t multIndex = (index - offset) * wordsize;
			if (0 <= multIndex && multIndex < data.size()) {
				return data.data() + multIndex;
			}
			return nullptr;
		}
	};
}