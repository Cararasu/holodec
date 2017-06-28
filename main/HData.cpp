#include "HData.h"

#include <string.h>
#include <fstream>
#include "HString.h"


holodec::HData::HData (uint8_t* data, size_t size, HString filename) : data (data), size (size), filename (filename) {

}
holodec::HData::HData (HData& file) : data ( (uint8_t*) malloc (file.size)), size (file.size), filename (file.filename) {
	memcpy (data, file.data, size);
}


holodec::HData::~HData() {
	free (data);
}