#pragma once

#include "Header.h"
#include "Array.h"

namespace holodec {

#define STRING_FORMAT ".*s"

	inline char* string_dup(const char* cstr, size_t size) {
		void* data = malloc(size);
		memcpy(data, cstr, size);
		return (char*)data;
	}
	inline char* string_dup(const char* cstr) {
		return string_dup(cstr, strlen(cstr) + 1);
	}

	inline constexpr uint64_t djb2_hash(const char* ptr, size_t size) {
		return ptr ? (size ? (djb2_hash(ptr + 1, size - 1) * 33) ^ *ptr : 5381) : 0;
	}

	struct String {
		static const size_t BUFFER_SIZE = sizeof(char*) + sizeof(size_t);

		union {
			struct {
				char* m_cstr;
				u64 m_hash;
			};
			struct {
				char m_data[BUFFER_SIZE];
			};
		};
		size_t m_size;

		String() {
			m_cstr = nullptr;
			m_size = 0;
			memset(m_data, 0, BUFFER_SIZE);
		}
		String(const char* cstr, size_t size) {
			m_size = size;
			if (m_size <= BUFFER_SIZE) {
				memcpy(m_data, cstr, m_size);
				memset(&m_data[m_size], 0, BUFFER_SIZE - m_size);
			}
			else {
				m_cstr = string_dup(cstr, m_size);
				m_hash = djb2_hash(m_cstr, m_size);
			}
		}
		String(const char* cstr) : String(cstr, strlen(cstr) + 1) {}
		String(const String& str) {
			m_size = str.size();
			if (m_size <= BUFFER_SIZE) {
				memcpy(m_data, str.m_data, BUFFER_SIZE);
			}
			else {
				m_cstr = string_dup(str.str(), str.size());
				m_hash = str.m_hash;
			}
		}
		String(String&& str) {
			m_size = str.m_size;
			if (m_size <= BUFFER_SIZE) {
				memcpy(m_data, str.m_data, BUFFER_SIZE);
			}
			else {
				m_cstr = string_dup(str.str(), str.size());
				m_hash = str.m_hash;
			}
		}
		String& operator= (const String& str) {
			m_size = str.m_size;
			if (m_size <= BUFFER_SIZE) {
				memcpy(m_data, str.m_data, BUFFER_SIZE);
			}
			else {
				m_cstr = string_dup(str.str(), str.size());
				m_hash = str.m_hash;
			}
			return *this;
		}
		String& operator= (String&& str) {
			m_size = str.m_size;
			if (m_size <= BUFFER_SIZE) {
				memcpy(m_data, str.m_data, BUFFER_SIZE);
			}
			else {
				m_cstr = string_dup(str.str(), str.size());
				m_hash = str.m_hash;
			}
			return *this;
		}
		String& operator= (const char* cstr) {
			m_size = strlen(cstr);
			if (m_size <= BUFFER_SIZE) {
				memcpy(m_data, cstr, m_size);
				memset(&m_data[m_size], 0, BUFFER_SIZE - m_size);
			}
			else {
				m_cstr = string_dup(cstr, m_size);
				m_hash = djb2_hash(cstr, m_size);
			}
			return *this;
		}
		~String() {
			if (m_size > BUFFER_SIZE) free(m_cstr);
		}
		operator bool() {
			return m_size != 0;
		}
		constexpr const char* str() const {
			if (m_size > BUFFER_SIZE) return m_cstr;
			else return m_data;
		}
		char* str() {
			return m_size > BUFFER_SIZE ? m_cstr : m_data;
		}
		size_t size() const {
			return m_size;
		}
		u64 hash() const {
			return m_size > BUFFER_SIZE ? m_hash : *(u64*)m_data;
		}
	};


	inline bool operator==(const String& lhs, const String& rhs) {
		return lhs.hash() == rhs.hash() ? strcmp(lhs.str(), rhs.str()) == 0 : false;
	}
	inline bool operator==(const String& lhs, const char* rhs) {
		return strcmp(lhs.str(), rhs) == 0;
	}
	inline bool operator==(const char* lhs, const String& rhs) {
		return strcmp(lhs, rhs.str()) == 0;
	}
	inline bool operator!=(const String& lhs, const String& rhs) {
		return !(lhs == rhs);
	}
	inline bool operator!=(const String& lhs, const char* rhs) {
		return !(lhs == rhs);
	}
	inline bool operator!=(const char* lhs, const String& rhs) {
		return !(lhs == rhs);
	}
	inline bool operator<(const String& lhs, const String& rhs) {
		return lhs.hash() == rhs.hash() ? strcmp(lhs.str(), rhs.str()) < 0 : lhs.hash() < rhs.hash();
	}
	inline bool operator<=(const String& lhs, const String& rhs) {
		return lhs.hash() == rhs.hash() ? strcmp(lhs.str(), rhs.str()) < 0 : lhs.hash() <= rhs.hash();
	}
	inline bool operator>(const String& lhs, const String& rhs) {
		return lhs.hash() == rhs.hash() ? strcmp(lhs.str(), rhs.str()) < 0 : lhs.hash() > rhs.hash();
	}
	inline bool operator>=(const String& lhs, const String& rhs) {
		return lhs.hash() == rhs.hash() ? strcmp(lhs.str(), rhs.str()) < 0 : lhs.hash() >= rhs.hash();
	}


	struct StringStore {

		struct StringWrapper {
			u64 id = 0;
			String string;
			u32 refcount = 0;
		};

		UIdArray<StringWrapper> stringlist;
		
		MultiMap<u64, u64> hash_map;

		u64 insert_string(String&& string) {
			u64 hash = string.hash();
			auto it_pair = hash_map.equal_range(hash);
			for (auto it = it_pair.first; (it != it_pair.second); ) {
				StringWrapper& wrap = stringlist[it->second];
				if (string == wrap.string) {
					wrap.refcount++;
					return wrap.id;
				}
				it++;
			}
			StringWrapper wrap;
			wrap.string = std::move(string);
			wrap.refcount++;
			u64 handle = stringlist.insert(std::move(wrap));
			hash_map.insert(std::make_pair(wrap.string.hash(), handle));
			return handle;
		}
		u64 insert_string(const String& string) {
			return insert_string(string.str(), string.size());
		}
		u64 insert_string(const char* cstr, size_t size) {
			return insert_string(String(cstr, size));
		}
		u64 insert_string(const char* cstr) {
			return insert_string(cstr, strlen(cstr));
		}
		u64 insert_string(u64 handle) {
			StringWrapper* entry = stringlist.get(handle);
			if (entry) entry->refcount++;
			return handle;
		}
		String* get_string(u64 handle) {
			StringWrapper* entry = stringlist.get(handle);
			if (entry) return &entry->string;
			return 0;
		}
		void remove_string(u64 handle) {
			StringWrapper* entry = stringlist.get(handle);
			if (entry) {
				if (--entry->refcount == 0) {
					u64 entry_id = entry->id;
					u64 hash = entry->string.hash();
					stringlist.remove(entry_id);
					auto it_pair = hash_map.equal_range(hash);
					for(auto it = it_pair.first; (it != it_pair.second); ) {
						if (it->second == entry_id) {
							it = hash_map.erase(it);
							continue;
						}
						it++;
					}
				}
			}
			else {
				//ERROR
			}
		}

		void print() {
			printf("StringStore\n");
			for (StringWrapper& wrapper : stringlist) {
				if(wrapper.id)
					printf("\t%" PRIx64 ": %.*s ref:%" PRIu32 "\n", wrapper.id, (int)wrapper.string.size(), wrapper.string.str(), wrapper.refcount);
			}
		}
	};
	struct ProxyString {
		static const size_t BUFFER_SIZE = sizeof(u64) + sizeof(StringStore*);
		union {
			struct {
				u64 id;
				StringStore* store;
			};
			struct {
				char data[BUFFER_SIZE];
			};
		};
		size_t _size = 0;

		void free() {
			if (_size > BUFFER_SIZE) {
				store->remove_string(id);
				_size = 0;
			}
		}
		void init(const char* str, size_t size, StringStore* store) {
			free();
			this->_size = size;
			if (size > BUFFER_SIZE) {
				this->id = store->insert_string(str, size);
				this->store = store;
			}
			else {
				memcpy(data, str, _size);
				memset(&data[_size], 0, BUFFER_SIZE - _size);
			}
		}
		void init_move(ProxyString* str) {
			free();
			this->_size = str->_size;
			if (this->_size > BUFFER_SIZE) {
				this->id = str->id;
				this->store = str->store;
			}
			else {
				memcpy(this->data, str->data, BUFFER_SIZE);
			}
		}

		ProxyString() {
			this->id = 0;
			this->store = nullptr;
			_size = 0;
		}
		ProxyString(const char* cstr, StringStore* store) {
			init(cstr, strlen(cstr) + 1, store);
		}
		ProxyString(const char* cstr, size_t size, StringStore* store) {
			init(cstr, size, store);
		}
		ProxyString(const ProxyString& str) {
			init(str.str(), str.size(), str.store);
		}
		ProxyString(ProxyString&& str) {
			init_move(&str);
			str._size = 0;
		}
		ProxyString(const String& str, StringStore* store) {
			init(str.str(), str.size(), store);
		}
		ProxyString(String&& str, StringStore* store) {
			init(str.str(), str.size(), store);
			str.m_size = 0;
		}

		ProxyString& operator= (const ProxyString& str) {
			init(str.str(), str.size(), str.store);
			return *this;
		}
		ProxyString& operator= (ProxyString&& str) {
			init_move(&str);
			str._size = 0;
			return *this;
		}
		~ProxyString() {
			free();
		}
		const char* str() const {
			if (_size <= BUFFER_SIZE) return data;
			else return store->get_string(id)->str();
		}
		char* str() {
			if (_size <= BUFFER_SIZE) return data;
			else return store->get_string(id)->str();
		}
		operator const char*() const {
			return str();
		}
		operator char*() {
			return str();
		}
		size_t size() const {
			return _size;
		}
	};

	struct StringRef {
		u32 id;
		ProxyString name;

		StringRef() : id(0), name() {}

		StringRef(const char* name, StringStore* store) : id(0), name(name, store) {}
		StringRef(const char* name, size_t size, StringStore* store) : id(0), name(name, size, store) {}

		StringRef(u32 id) : id(id), name() {}

		StringRef(const String& name, StringStore* store) : id(0), name(name.str(), name.size(), store) {}
		StringRef(String&& name, StringStore* store) : id(0), name(name.str(), name.size(), store) {}

		StringRef(const String& name, StringStore* store, u32 id) : id(id), name(name.str(), name.size(), store) {}
		StringRef(String&& name, StringStore* store, u32 id) : id(id), name(name.str(), name.size(), store) {}

		StringRef(const ProxyString& name) : id(0), name(name) {}
		StringRef(ProxyString&& name) : id(0), name(std::move(name)) {}

		StringRef(const ProxyString& name, u32 id) : id(id), name(name) {}
		StringRef(ProxyString&& name, u32 id) : id(id), name(std::move(name)) {}

		StringRef(const StringRef& ref) : id(ref.id), name(ref.name) {}
		StringRef(StringRef&& ref) : id(ref.id), name(std::move(ref.name)) {}

		StringRef& operator=(const StringRef& ref) {
			id = ref.id;
			name = ref.name;
			return *this;
		}
		StringRef& operator=(StringRef&& ref) {
			id = ref.id;
			name = std::move(ref.name);
			return *this;
		}

		explicit operator bool() {
			return name.size() != 0;
		}
		explicit operator u32() {
			return id;
		}
	};
	inline bool operator==(StringRef& lhs, StringRef& rhs) {
		if (lhs.name == rhs.name) return true;
		return lhs.id == rhs.id;
	}

	struct StringURef {
		u64 handle;
		ProxyString name;

		StringURef() : handle(0), name() {}

		StringURef(const char* name, StringStore* store) : handle(0), name(name, store) {}
		StringURef(const char* name, size_t size, StringStore* store) : handle(0), name(name, size, store) {}

		StringURef(u64 handle) : handle(handle), name() {}

		StringURef(const String& name, StringStore* store) : handle(0), name(name.str(), name.size(), store) {}
		StringURef(String&& name, StringStore* store) : handle(0), name(name.str(), name.size(), store) {}

		StringURef(const String& name, StringStore* store, u64 handle) : handle(handle), name(name.str(), name.size(), store) {}
		StringURef(String&& name, StringStore* store, u64 handle) : handle(handle), name(name.str(), name.size(), store) {}

		StringURef(const ProxyString& name) : handle(0), name(name) {}
		StringURef(ProxyString&& name) : handle(0), name(std::move(name)) {}

		StringURef(const ProxyString& name, u64 handle) : handle(handle), name(name) {}
		StringURef(ProxyString&& name, u64 handle) : handle(handle), name(std::move(name)) {}

		StringURef(const StringURef& ref) : handle(ref.handle), name(ref.name) {}
		StringURef(StringURef&& ref) : handle(ref.handle), name(std::move(ref.name)) {}

		StringURef& operator=(const StringURef& ref) {
			handle = ref.handle;
			name = ref.name;
			return *this;
		}
		StringURef& operator=(StringURef&& ref) {
			handle = ref.handle;
			name = std::move(ref.name);
			return *this;
		}

		explicit operator bool() {
			return name.size() != 0;
		}
		explicit operator u64() {
			return handle;
		}
	};
	inline bool operator==(StringURef& lhs, StringURef& rhs) {
		u32 lhuid = unpack_uid_from_handle(lhs.handle);
		u32 rhuid = unpack_uid_from_handle(rhs.handle);
		if (lhuid && lhuid == rhuid) return true;
		return lhs.name == rhs.name;
	}

#define STRINGBUFFER_SIZE (1024)
	struct StringBuilder {
		struct StringBuilderBuffer {
			char buffer[STRINGBUFFER_SIZE];
			StringBuilderBuffer* next = nullptr;
		} head;
		u64 char_index = 0;
		StringBuilderBuffer *last_block;

		StringBuilder() : head(), char_index(0), last_block(&head) {}
		~StringBuilder() {
			StringBuilderBuffer* buffer = head.next;
			while (buffer) {
				StringBuilderBuffer* tptr = buffer;
				buffer = buffer->next;
				delete tptr;
			}
		}

		u64 size() {
			return char_index + 1;
		}

		void create_new_block() {
			last_block->next = new StringBuilderBuffer();
			last_block = last_block->next;
		}
		StringBuilder& append_char(char c) {
			last_block->buffer[char_index % STRINGBUFFER_SIZE] = c;
			char_index++;
			if (!(char_index % STRINGBUFFER_SIZE)) create_new_block();
			return *this;
		}
		StringBuilder& append(const char* cstr) {
			return append(cstr, strlen(cstr));
		}
		StringBuilder& append(const char* cstr, s64 length) {
			s64 block_capacity = (((char_index / STRINGBUFFER_SIZE) + 1) * STRINGBUFFER_SIZE);
			s64 charsleft = (char_index + length) - block_capacity;
			if (charsleft >= 0) {
				u64 tocopy = length - charsleft;
				memcpy(last_block->buffer + (char_index % STRINGBUFFER_SIZE), cstr, tocopy);
				cstr += tocopy;
				char_index = block_capacity;
				create_new_block();
			}
			else {
				memcpy(last_block->buffer + (char_index % STRINGBUFFER_SIZE), cstr, length);
				char_index += length;
				return *this;
			}
			while (charsleft >= STRINGBUFFER_SIZE) {
				memcpy(last_block->buffer, cstr, STRINGBUFFER_SIZE);
				cstr += STRINGBUFFER_SIZE;
				char_index += STRINGBUFFER_SIZE;
				charsleft -= STRINGBUFFER_SIZE;
				create_new_block();
			}
			if (charsleft) {
				memcpy(last_block->buffer + (char_index % STRINGBUFFER_SIZE), cstr, charsleft);
				char_index += charsleft;
			}
			return *this;
		}
		StringBuilder& append(String& str) {
			append(str.m_cstr);
			return *this;
		}

		StringBuilder& append(u64 value, int base = 10) {
			assert(base <= 16);
			u32 count = 1;
			u64 tvalue = value / base;
			while (tvalue) {
				tvalue /= base;
				count++;
			}
			char buffer[520];//with base 2 the max size is 512
			for (u32 i = 1; i <= count; i++) {
				int digit = value % base;
				value /= base;
				if (digit < 10) {
					buffer[count - i] = '0' + digit;
				}
				else {
					buffer[count - i] = 'a' - 10 + digit;
				}
			}
			append(buffer, count);
			return *this;
		}
		StringBuilder& append(u32 value, int base = 10) {
			assert(base <= 16);
			u32 count = 1;
			u64 tvalue = value / base;
			while (tvalue) {
				tvalue /= base;
				count++;
			}
			char buffer[260];//with base 2 the max size is 256
			for (u32 i = 1; i <= count; i++) {
				int digit = value % base;
				value /= base;
				if (digit < 10) {// 0 - 9
					buffer[count - i] = '0' + digit;
				}
				else {// a - f
					buffer[count - i] = 'a' - 10 + digit;
				}
			}
			append(buffer, count);
			return *this;
		}

		StringBuilder& append(s64 value, int base = 10) {
			//TODO
			return *this;
		}
		StringBuilder& append(s32 value, int base = 10) {
			//TODO
			return *this;
		}

		StringBuilder& append(f64 value, int base = 10/*, int afterpoint*/) {
			//TODO
			return *this;
		}
		StringBuilder& append(f32 value, int base = 10/*, int afterpoint*/) {
			//TODO
			return *this;
		}

		String build() {
			char* ptr = (char*)malloc(char_index + 1);
			char* iptr = ptr;
			s64 bytesleft = char_index;
			StringBuilderBuffer* buffer = &head;
			while (buffer && bytesleft >= 0) {
				s64 bytes_to_copy = bytesleft > STRINGBUFFER_SIZE ? STRINGBUFFER_SIZE : bytesleft;
				memcpy(iptr, buffer->buffer, bytes_to_copy);
				iptr += bytes_to_copy;
				bytesleft -= bytes_to_copy;
				buffer = buffer->next;
			}
			ptr[char_index] = '\0';
			assert(!buffer);
			//TODO can be done with only one malloc and not 2 as it is now
			return String(ptr);
		}
	};
#undef STRINGBUFFER_SIZE

}