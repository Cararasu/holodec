#pragma once

namespace holodec {

	struct DataSource {
		u8* m_data = nullptr;
		size_t m_size = 0;
	};

	bool load_file(const char* file, DataSource* source);

	struct DataPatch {
		u64 m_addr = 0, m_size = 0;;
		u8* m_data = nullptr;

		bool is_mapped(u64 addr) {
			return m_addr <= addr && addr < (m_addr + m_size);
		}
	};

	struct DataSegment {
		u64 m_addr = 0, m_size = 0;
		u8* m_data = nullptr;
		DynArray<DataPatch> m_patches;

		bool is_mapped(u64 addr) {
			return m_addr <= addr && addr < (m_addr + m_size);
		}
		bool bytes_left(u64 addr) {
			return is_mapped(addr) ? (m_size - (addr - m_addr)) : 0;
		}

		bool get_byte( size_t addr, u8* dst_ptr);

		size_t copy_data(void* dst_ptr, size_t count, size_t addr);
	};
}