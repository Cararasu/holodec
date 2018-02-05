#ifndef H_FILE_H
#define H_FILE_H

#include <stdint.h>
#include "General.h"

namespace holodec {

	struct Data {
		HString filename;

		Data(const HString filename) : filename(filename) {}
		Data(Data& file) = default;
		Data(Data && file) = default;
		virtual ~Data() {};

		virtual uint8_t& operator[] (size_t index) = 0;
		virtual size_t size() = 0;

		template<typename T>
		inline T* get(size_t index) {
			return (T*)(&(*this)[index]);
		}


	};
	struct PlainData : public Data {
		const size_t m_size;
		uint8_t* const m_data;

		PlainData(uint8_t* data, size_t size, const HString filename);
		PlainData(PlainData& file);
		PlainData(PlainData && file);
		virtual ~PlainData();

		virtual size_t size() {
			return m_size;
		}

		inline uint8_t& operator[] (size_t index) {
			if(index >= m_size)
				throw std::out_of_range("Plain OOR");
			return m_data[index];
		}
	};
	struct DataSegment {
		uint64_t offset;
		std::vector<uint8_t> data;
	};
	struct IHexData : public Data {
		uint64_t m_size;
		Data* m_data;
		HList<DataSegment> dataSegments;

		IHexData(Data* data);
		IHexData(IHexData& file) = default;
		IHexData(IHexData && file) = default;
		virtual ~IHexData() = default;

		virtual size_t size() {
			return m_size;
		}

		inline uint8_t& operator[] (size_t index) {
			for (DataSegment& dataSegment : dataSegments) {
				if (dataSegment.offset <= index && index < dataSegment.offset + dataSegment.data.size())
					return dataSegment.data[index - dataSegment.offset];
			}
			throw std::out_of_range ("IHex OOR");
		}
	};
}

#endif // H_FILE_H
