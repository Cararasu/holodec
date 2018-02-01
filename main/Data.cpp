#include "Data.h"

#include <string.h>
#include <fstream>
#include "HString.h"


holodec::PlainData::PlainData(uint8_t* data, size_t size, HString filename) 
	: Data(filename), m_size(size), m_data (data) {

}
holodec::PlainData::PlainData(PlainData& file) 
	: Data(file.filename), m_size(file.m_size), m_data ( (uint8_t*) malloc (file.m_size)) {
	memcpy (m_data, file.m_data, m_size);
}


holodec::PlainData::~PlainData() {
	free (m_data);
}