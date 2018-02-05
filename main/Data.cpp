#include "Data.h"

#include <assert.h>
#include <string.h>
#include <fstream>
#include "HString.h"

namespace holodec {

	PlainData::PlainData(uint8_t* data, size_t size, HString filename)
		: Data(filename), m_size(size), m_data(data) {

	}
	PlainData::PlainData(PlainData& file)
		: Data(file.filename), m_size(file.m_size), m_data((uint8_t*)malloc(file.m_size)) {
		memcpy(m_data, file.m_data, m_size);
	}


	PlainData::~PlainData() {
		free(m_data);
	}

	uint64_t charToInt(uint8_t c) {
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
	inline uint64_t parse8BitHex(uint8_t* c) {
		return charToInt(c[0]) << 4 | charToInt(c[1]);
	}
	inline uint64_t parse16BitHex(uint8_t* c) {
		return parse8BitHex(c) << 8 | parse8BitHex(c + 2);
	}
	inline uint64_t parse32BitHex(uint8_t* c) {
		return parse16BitHex(c) << 16 | parse16BitHex(c+2);
	}
	IHexData::IHexData(Data* data) : Data(data->filename), m_data(data) {
		uint64_t index = 0;
		while (uint8_t* dataptr = data->get<uint8_t>(index)) {
			assert(dataptr[0] == ':');
			uint64_t size = parse8BitHex(dataptr + 1);
			uint64_t offset = parse16BitHex(dataptr + 3);
			uint64_t type = parse8BitHex(dataptr + 7);
			switch (type) {
			case 0x00: {

				DataSegment* appendSegment = nullptr;
				for (DataSegment& dataSegment : dataSegments) {
					if (dataSegment.offset + dataSegment.data.size() == offset) {
						appendSegment = &dataSegment;
						break;
					}
				}
				if (!appendSegment) {
					dataSegments.emplace_back();
					appendSegment = &dataSegments.back();
					appendSegment->data.resize(size);
					appendSegment->offset = offset;
				}
				else {
					appendSegment->data.resize(appendSegment->data.size() + size);
				}

				index += 0x9;
				for (int i = 0; i < size; i++) {
					appendSegment->data[offset + i - appendSegment->offset] = parse8BitHex(dataptr + 0x09 + 2*i);
					index += 0x02;
				}
				index += 0x02;
			}
				break;
			case 0x01: {
				this->m_size = 0x00;
				for (DataSegment& dataSegment : dataSegments) {
					this->m_size += dataSegment.data.size();
				}
				return;
			}
				break;
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
			while (index < data->size() && (*data)[index] != ':')index++;
		}

	}


}
