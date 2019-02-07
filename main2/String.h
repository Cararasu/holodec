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
		return string_dup(cstr, strlen(cstr));
	}

	inline constexpr uint64_t djb2_hash(const char* ptr, size_t size) {
		return ptr ? (size ? (djb2_hash(ptr + 1, size - 1) * 33) ^ *ptr : 5381) : 0;
	}

	struct String {
		static const size_t BUFFER_SIZE = sizeof(char*) + sizeof(size_t);

		union {
			struct {
				char* cstr;
				size_t hash;
			};
			struct {
				char data[BUFFER_SIZE];
			};
		};

		size_t _size;

		String() {
			cstr = nullptr;
			hash = 0;
			_size = 0;
		}
		String(const char* cstr) {
			_size = strlen(cstr);
			if (_size <= BUFFER_SIZE) {
				memcpy(data, cstr, _size);
				memset(&data[_size], 0, BUFFER_SIZE - _size);
			}
			else {
				this->cstr = string_dup(cstr, _size);
				hash = djb2_hash(cstr, _size);
			}
		}
		String(const char* cstr, size_t size) {
			_size = size;
			if (_size <= BUFFER_SIZE) {
				memcpy(data, cstr, _size);
				memset(&data[_size], 0, BUFFER_SIZE - _size);
			}
			else {
				this->cstr = string_dup(cstr, size);
				hash = djb2_hash(cstr, size);
			}
		}
		String(const String& str) {
			_size = str._size;
			if (_size <= BUFFER_SIZE) {
				memcpy(data, str.data, BUFFER_SIZE);
			}
			else {
				cstr = string_dup(str.str(), str.size());
				hash = str.hash;
			}
		}
		String(String&& str) {
			_size = str._size;
			if (_size <= BUFFER_SIZE) {
				memcpy(data, str.data, BUFFER_SIZE);
			}
			else {
				cstr = string_dup(str.str(), str.size());
				hash = str.hash;
			}
		}
		String& operator= (const String& str) {
			_size = str._size;
			if (_size <= BUFFER_SIZE) {
				memcpy(data, str.data, BUFFER_SIZE);
			}
			else {
				cstr = string_dup(str.str(), str.size());
				hash = str.hash;
			}
			return *this;
		}
		String& operator= (String&& str) {
			_size = str._size;
			if (_size <= BUFFER_SIZE) {
				memcpy(data, str.data, BUFFER_SIZE);
			}
			else {
				cstr = string_dup(str.str(), str.size());
				hash = str.hash;
			}
			return *this;
		}
		String& operator= (const char* cstr) {
			_size = strlen(cstr);
			if (_size <= BUFFER_SIZE) {
				memcpy(data, cstr, _size);
				memset(&data[_size], 0, BUFFER_SIZE - _size);
			}
			else {
				this->cstr = string_dup(cstr, _size);
				hash = djb2_hash(cstr, _size);
			}
			return *this;
		}
		~String() {
			if (_size > BUFFER_SIZE) free(cstr);
		}
		operator bool() {
			return _size != 0;
		}
		constexpr const char* str() const {
			if (_size > BUFFER_SIZE) return cstr;
			else return data;
		}
		char* str() {
			return _size > BUFFER_SIZE ? cstr : data;
		}
		size_t size() const {
			return _size;
		}
	};


	inline bool operator==(const String& lhs, const String& rhs) {
		return lhs.hash == rhs.hash ? strcmp(lhs.str(), rhs.str()) == 0 : false;
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
		return lhs.hash < rhs.hash ? true : strcmp(lhs.str(), rhs.str()) < 0;
	}
	inline bool operator<=(const String& lhs, const String& rhs) {
		return lhs.hash <= rhs.hash ? true : strcmp(lhs.str(), rhs.str()) <= 0;
	}
	inline bool operator>(const String& lhs, const String& rhs) {
		return lhs.hash > rhs.hash ? true : strcmp(lhs.str(), rhs.str()) > 0;
	}
	inline bool operator>=(const String& lhs, const String& rhs) {
		return lhs.hash >= rhs.hash ? true : strcmp(lhs.str(), rhs.str()) >= 0;
	}


	struct StringStore {

		struct StringWrapper {
			u64 id = 0;
			String string;
			u32 refcount = 0;
		};

		UIdArray<StringWrapper> stringlist;

		u64 insert_string(const char* cstr, size_t size) {
			for (StringWrapper& entry : stringlist) {
				if (entry.string.size() == size && entry.string == cstr) {
					entry.refcount++;
					return entry.id;
				}
			}
			StringWrapper wrap;
			wrap.string = String(cstr, size);
			wrap.refcount++;
			return stringlist.insert(wrap);
		}
		u64 insert_string(const char* cstr) {
			return insert_string(cstr, strlen(cstr));
		}
		u64 insert_string(u64 handle) {
			StringWrapper* entry = stringlist.get(handle);
			if (entry) entry->refcount++;
			return handle;
		}
		u64 insert_string(String& string) {
			return insert_string(string.str(), string.size());
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
					stringlist.remove(entry->id);
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
			init(cstr, strlen(cstr), store);
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
			str._size = 0;
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
			append(str.cstr);
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
			char buffer[150];//with base 2 the max size is 128
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
			char buffer[100];//with base 2 the max size is 64
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
			return String(ptr);
		}
	};
#undef STRINGBUFFER_SIZE

}