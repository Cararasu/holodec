#pragma once


namespace holodec {
	struct Binary;

	Binary* load_binary_file(const char* path);
	Binary* load_binary_memory(void* memory, size_t size, bool copydata = true);


	bool parse_conf_file(const char* filename);

}

