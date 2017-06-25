#include "RData.h"

#include <string.h>
#include <fstream>
#include "RString.h"


holodec::RData::RData (uint8_t* data, size_t size, RString filename) : data (data), size (size), filename (filename) {

}
holodec::RData::RData (RData& file) : data ( (uint8_t*) malloc (file.size)), size (file.size), filename (file.filename) {
	memcpy (data, file.data, size);
}


holodec::RData::~RData() {
	free (data);
}