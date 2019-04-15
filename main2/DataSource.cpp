
#include "pch.h"
#include "DataSource.h"

#include <stdio.h>
#include <stdlib.h>

namespace holodec {

	bool load_file(const char* file, DataSource* source) {

		FILE *f = fopen(file, "rb");

		if (f) {

			fseek(f, 0, SEEK_END);
			source->m_size = ftell(f);
			fseek(f, 0, SEEK_SET);

			source->m_data = static_cast<u8*>(malloc(source->m_size));
			fread(source->m_data, source->m_size, 1, f);
			fclose(f);
			return true;
		}
		return false;
	}

	bool DataSegment::get_byte(u64 addr, u8* dst_ptr) {
		if (is_mapped(addr)) {
			//TODO improve the patches, because this is slow and bad if there are a lot of patches
			for (DataPatch& patch : m_patches) {
				if (patch.is_mapped(addr)) {
					if (patch.m_data) {
						*dst_ptr = patch.m_data[addr - patch.m_addr];
						return true;
					}
				}
			}
			*dst_ptr = m_data[addr - m_addr];
			return true;
		}
		return false;
	}

	u64 DataSegment::copy_data(void* dst_ptr, u64 count, uint64_t addr) {
		u64 i = 0;
		for (; i < count; i++) {
			//TODO improve on this
			if (!get_byte(addr + i, static_cast<u8*>(dst_ptr))) {
				return i;
			}
		}
		return i;
	}
}