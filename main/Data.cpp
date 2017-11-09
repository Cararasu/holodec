#include "Data.h"

#include <string.h>
#include <fstream>
#include "HString.h"


holodec::Data::Data (uint8_t* data, size_t size, HString filename) : data (data), size (size), filename (filename) {

}
holodec::Data::Data (Data& file) : data ( (uint8_t*) malloc (file.size)), size (file.size), filename (file.filename) {
	memcpy (data, file.data, size);
}


holodec::Data::~Data() {
	free (data);
}