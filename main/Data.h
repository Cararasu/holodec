#ifndef H_FILE_H
#define H_FILE_H

#include <stdint.h>
#include "HString.h"

namespace holodec {

	struct Data {
		HString filename;

		Data(const HString filename) : filename(filename) {}
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
			return m_data[index];
		}
	};
}

#endif // H_FILE_H
