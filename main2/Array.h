#pragma once

#include "Header.h"
#include <map>

namespace holodec {


	struct NopAllocator {
		void* allocate(size_t size, size_t alignment) {
			return malloc(size);
		}
		void* reallocate(void* data, size_t size, size_t alignment) {
			return realloc(data, size);
		}
		void free(void* data) {
			::free(data);
		}
	};
	template<typename T, typename ALLOC>
	inline T* t_allocate(ALLOC* allocator, size_t count) {
		if (allocator) return reinterpret_cast<T*> (allocator->allocate(count * sizeof(T), alignof (T)));
		else return reinterpret_cast<T*> (malloc(count * sizeof(T)));
	}
	template<typename T, typename ALLOC>
	inline T* t_reallocate(ALLOC* allocator, T* old_ptr, size_t count) {
		if (allocator) return reinterpret_cast<T*> (allocator->reallocate(old_ptr, count * sizeof(T), alignof (T)));
		else return reinterpret_cast<T*> (realloc(old_ptr, count * sizeof(T)));
	}
	template<typename T, typename ALLOC>
	inline void t_free(ALLOC* allocator, T* ptr) {
		if (allocator) allocator->free(ptr);
		else free(ptr);
	}

	template<typename T, typename ALLOC = NopAllocator>
	struct Array;
	template<typename T, typename ALLOC = NopAllocator>
	struct DynArray;
	template<typename T, u32 LOCALSIZE = 4,  typename ALLOC = NopAllocator >
	struct StaticDynArray;
	template<typename T, typename ALLOC = NopAllocator>
	struct IdArray;
	template<typename T, typename ALLOC = NopAllocator>
	struct IdPtrArray;
	template<typename T, typename ALLOC = NopAllocator>
	struct UIdArray;
	template<typename T, typename ALLOC = NopAllocator>
	struct UIdPtrArray;

	template<typename S, typename T>
	using Map = std::map<S, T>;

	template<typename T, typename ALLOC>
	struct Array {

		size_t size = 0;
		T* data = nullptr;
		ALLOC* allocator = nullptr;

		typedef T* iterator;

		void free() {
			if (data) {
				for (size_t i = 0; i < size; i++) {
					data[i].~T();
					t_free<T, ALLOC>(allocator, data);
				}
				size = 0;
				data = nullptr;
			}
		}

		Array(ALLOC* allocator = nullptr) : size(0), data(nullptr), allocator(allocator) {}

		Array(size_t size, ALLOC* allocator) : size(size), data(nullptr), allocator(allocator) {
			if (size) {
				data = t_allocate<T, ALLOC>(allocator, size);
				for (int i = 0; i < size; i++) {
					new (&data[i]) T;
				}
			}
		}
		Array(size_t size, const T& ele, ALLOC* allocator) : size(size), data(nullptr), allocator(allocator) {
			if (size) {
				data = t_allocate<T, ALLOC>(allocator, size);
				for (size_t i = 0; i < size; i++) {
					new (&data[i]) T(ele);
				}
			}

		}
		Array(const Array<T, ALLOC>& array) : size(array.size), data(nullptr), allocator(array.allocator) {
			if (size) {
				data = t_allocate<T, ALLOC>(allocator, size);
				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(array.data[i]);
				}
			}
		}
		Array(const Array<T, ALLOC>&& array) : size(array.size), data(array.data), allocator(array.allocator) {
			array.size = 0;
			array.data = nullptr;
		}
		Array<T, ALLOC>& operator= (const std::initializer_list<T> init_list) {
			free();
			size = init_list.size();
			if (size) {
				data = t_allocate<T, ALLOC>(allocator, size);

				for (int i = 0; i < init_list.size(); i++) {
					new (&data[i]) T(init_list[i]);
				}
			}
			return *this;
		}
		Array<T, ALLOC>& operator= (const Array<T, ALLOC>& array) {
			free();
			data = nullptr;
			size = array.size;
			if (size) {
				data = t_allocate<T, ALLOC>(allocator, size);

				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(std::move(array[i]));
					i++;
				}
			}
			return *this;
		}
		Array<T, ALLOC>& operator= (Array<T, ALLOC>&& array) {
			free();
			data = array.data;
			array.data = nullptr;
			size = array.size;
			array.size = 0;
			allocator = array.allocator;
			return *this;
		}
		~Array() {
			free();
		}
		void resize(size_t size, const T& ele) {
			data = t_reallocate<T, ALLOC>(allocator, data, size);
			for (size_t i = this->size; i < size; i++) {
				new (data[i]) T(ele);
			}
			this->size = size;
		}

		T& operator[] (size_t i) {
			return data[i];
		}
		const T& operator[] (size_t i) const {
			return data[i];
		}
		iterator begin() {
			return data;
		}
		iterator end() {
			return data + size;
		}
		const iterator begin() const {
			return data;
		}
		const iterator end() const {
			return data + size;
		}
	};

	template<typename T, typename ALLOC> 
	struct DynArray {

		size_t size = 0, capacity = 0;
		T* data = nullptr;
		ALLOC* allocator = nullptr;

		typedef T* iterator;

		void free() {
			if (data) {
				for (size_t i = 0; i < size; i++) {
					data[i].~T();
				}
				t_free<T, ALLOC>(allocator, data);
				size = 0;
				capacity = 0;
				data = nullptr;
			}
		}

		DynArray(ALLOC* allocator = nullptr) : size(0), capacity(0), data(nullptr), allocator(allocator) {}

		DynArray(size_t size, ALLOC* allocator) : size(size), capacity(0), data(nullptr), allocator(allocator) {
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T, ALLOC>(allocator, capacity);
				for (int i = 0; i < size; i++) {
					new (&data[i]) T;
				}
			}
		}
		DynArray(size_t size, size_t capacity, ALLOC* allocator) : size(size), capacity(capacity), data(nullptr), allocator(allocator) {
			if (size || capacity) {
				while (capacity < size) capacity *= 2;
				data = t_allocate<T, ALLOC>(allocator, capacity);
				for (int i = 0; i < size; i++) {
					new (&data[i]) T;
				}
			}
		}
		DynArray(size_t size, const T& ele, ALLOC* allocator) : size(size), capacity(8), data(nullptr), allocator(allocator) {
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T, ALLOC>(allocator, capacity);
				for (size_t i = 0; i < size; i++) {
					new (&data[i]) T(ele);
				}
			}

		}
		DynArray(const DynArray<T, ALLOC>& array) : size(array.size), capacity(array.capacity), data(nullptr), allocator(array.allocator) {
			if (size) {
				data = t_allocate<T, ALLOC>(allocator, capacity);
				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(array.data[i]);
				}
			}
		}
		DynArray(const DynArray<T, ALLOC>&& array) : size(array.size), capacity(array.capacity), data(array.data), allocator(array.allocator) {
			array.size = 0;
			array.capacity = 0;
			array.data = nullptr;
		}
		DynArray<T, ALLOC>& operator= (const std::initializer_list<T> init_list) {
			free();
			capacity = 0;
			size = init_list.size();
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T, ALLOC>(allocator, capacity);

				for (int i = 0; i < init_list.size(); i++) {
					new (&data[i]) T(init_list[i]);
				}
			}
			return *this;
		}
		DynArray<T, ALLOC>& operator= (const DynArray<T, ALLOC>& array) {
			free();
			data = nullptr;
			capacity = 0;
			size = array.size;
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T, ALLOC>(allocator, capacity);

				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(std::move(array[i]));
					i++;
				}
			}
			return *this;
		}
		DynArray<T, ALLOC>& operator= (DynArray<T, ALLOC>&& array) {
			free();

			data = array.data;
			array.data = nullptr;
			size = array.size;
			array.size = 0;
			capacity = array.capacity;
			array.capacity = 0;
			allocator = array.allocator;
			return *this;
		}
		~DynArray() {
			free();
		}

		void reserve(size_t min_capacity) {
			if (min_capacity > this->capacity) {
				capacity = MAX(capacity, 8);
				while (capacity < min_capacity) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
		}
		void shrink(size_t min_capacity = 0) {
			if (!size && !min_capacity) {
				t_free<T, ALLOC>(allocator, data);
				data = nullptr;
				capacity = 0;
			}
			else if (min_capacity > this->capacity) {
				capacity = MAX(capacity, 8);
				while (capacity < min_capacity) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
		}
		void push_back(T&& ele) {
			size_t neededcap = size + 1;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
			new (&data[size++]) T(std::move(ele));
		}
		T* push_back(T& ele) {
			size_t neededcap = size + 1;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
			new (&data[size]) T(ele);
			return &data[size++];
		}
		void push_back(T&& ele, size_t count) {
			size_t neededcap = size + count;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
			for (; size < neededcap; size++) {
				new (&data[size]) T(ele);
			}
		}
		void push_back(T& ele, size_t count) {
			size_t neededcap = size + count;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
			for (; size < neededcap; size++) {
				new (&data[size]) T(ele);
			}
		}
		template< class... Args >
		T* emplace_back(Args&&... args) {
			size_t neededcap = size + 1;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
			new (&data[size]) T(std::forward<Args>(args)...);
			return &data[size++];
		}
		void pop_back(size_t count = 1) {
			data[--size].~T();
		}
		T& back() {
			return data[size - 1];
		}

		void clear() {
			for (size_t i = 0; i < size; i++) {
				data[i].~T();
			}
			size = 0;
		}
		void resize(size_t size, const T& ele) {
			if (size > capacity) {
				capacity = MAX(capacity, 8);
				while (capacity < size) capacity *= 2;
				data = t_reallocate<T, ALLOC>(allocator, data, capacity);
			}
			for (size_t i = this->size; i < size; i++) {
				new (data[i]) T(ele);
			}
			this->size = size;
		}

		T& operator[] (size_t i) {
			return data[i];
		}
		const T& operator[] (size_t i) const {
			return data[i];
		}
		iterator begin() {
			return data;
		}
		iterator end() {
			return data + size;
		}
		const iterator begin() const {
			return data;
		}
		const iterator end() const {
			return data + size;
		}
	};

	template<typename T, u32 LOCALSIZE, typename ALLOC>
	struct StaticDynArray {

		size_t size = 0, capacity = 0;
		T* data = nullptr;
		T localarr[LOCALSIZE];
		ALLOC* allocator = nullptr;

		struct iterator {
			StaticDynArray<T, LOCALSIZE, ALLOC>* arr;
			size_t i = 0;
		};
		//TODO
	};

	template<typename T, typename ALLOC>
	inline void free_backing_id_dynarray(DynArray<T, ALLOC>* list) {
		if (list->data) {
			for (size_t i = 0; i < list->size; i++) {
				if (list->data[i].id) list->data[i].~T();
			}
			t_free<T, ALLOC>(list->allocator, list->data);
			list->size = 0;
			list->capacity = 0;
			list->data = nullptr;
		}
	}


	class IdGenerator {
		u32 val = 0;
	public:
		u32 next() {
			return ++val;
		}
		void clear() {
			val = 0;
		}
	};
	template<typename T, typename ALLOC>
	struct IdArray {
		DynArray<T, ALLOC> list;
		typedef typename DynArray<T, ALLOC>::iterator iterator;


		IdArray() {}
		IdArray(std::initializer_list<T> list) : list(list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i].id = i + 1;
			}
			this->list.insert(list.begin(), list.end(), this->list.begin());
		}
		IdArray(DynArray<T> list) : list(list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i].id = i + 1;
			}
			this->list.insert(list.begin(), list.end(), this->list.begin());
		}
		~IdArray() {
			free_backing_id_dynarray<T, ALLOC>(&list);
		}

		u32 insert(const T&& ele) {
			for (size_t i = 0; i < list.size(); i++) {
				if (!list[i].id) {
					u32 id = i + 1;
					list[i] = std::move(ele);
					list[i].id = id;
					return id;
				}
			}
			u32 id = list.size() + 1;
			list.push_back(std::move(ele));
			list.back().id = id;
			return id;
		}
		u32 insert(T& ele) {
			for (size_t i = 0; i < list.size; i++) {
				if (!list[i].id) {
					u32 id = (u32)(i + 1);
					list[i] = ele;
					list[i].id = id;
					return id;
				}
			}
			u32 id = (u32)(list.size + 1);
			list.push_back(ele);
			list.back().id = id;
			return id;
		}
		auto begin() -> decltype (list.begin()) {
			return list.begin();
		}
		auto end() -> decltype (list.end()) {
			return list.end();
		}
		size_t size() {
			return list.size;
		}
		auto back() -> decltype (list.back()) {
			return list.back();
		}
		iterator erase(iterator it) {
			it->id = 0;
			return ++it;
		}
		void remove(u32 id) {
			T* ptr = get(id);
			if (ptr->id) {
				ptr->~T();
				ptr->id = 0;
			}
		}
		T* get(u32 id) {
			return id && id <= list.size ? &list[id - 1] : nullptr;
		}
		T& operator[] (u32 id) {
			return *get(id);
		}
		void clear() {
			list.clear();
		}
	};

	inline u32 unpack_id_from_handle(u64 handle) {
		return (u32)(handle >> 32);
	}
	inline u32 unpack_uid_from_handle(u64 handle) {
		return (u32)handle;
	}
	inline u64 pack_handle(u32 id, u32 uid) {
		return (((u64)id) << 32) | (u64)uid;
	}

	template<typename T, typename ALLOC>
	struct UIdArray {
		IdGenerator gen;
		DynArray<T, ALLOC> list;

		typedef typename DynArray<T>::iterator iterator;

		UIdArray() {}
		UIdArray(std::initializer_list<T> init_list) : list(init_list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i]->id = pack_handle(i + 1, gen.next());
			}
		}
		UIdArray(DynArray<T>& dynarray) : list(dynarray.list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i]->id = pack_handle(i + 1, gen.next());
			}
		}
		~UIdArray() {
			free_backing_id_dynarray<T, ALLOC>(&list);
		}

		u64 insert(T& ele) {
			for (size_t i = 0; i < list.size; i++) {
				if (!list[i].id) {
					ele.id = pack_handle((u32)i + 1, gen.next());
					list[i] = ele;
					return ele.id;
				}
			}
			ele.id = pack_handle((u32)list.size + 1, gen.next());
			list.push_back(ele);
			return ele.id;
		}
		auto begin() -> decltype (list.begin()) {
			return list.begin();
		}
		auto end() -> decltype (list.end()) {
			return list.end();
		}
		auto size() -> decltype (list.size) {
			return list.size();
		}
		auto back() -> decltype (list.back()) {
			return list.back();
		}
		iterator erase(iterator it) {
			it->id = 0;
			return ++it;
		}
		T* get(u64 handle) {
			u32 id = unpack_id_from_handle(handle);
			T* ptr = get(id);
			return ptr && ptr->id == handle ? ptr : nullptr;
		}
		T* get(u32 id) {
			return id && id <= list.size ? &list[id - 1] : nullptr;
		}
		void remove(u64 handle) {
			T* ptr = get(handle);
			if (ptr) {
				ptr->~T();
				ptr->id = 0;
			}
		}
		T& operator[] (u64 handle) {
			return *get(handle);
		}
		void clear() {
			list.clear();
		}
	};

	template<typename T, typename ALLOC>
	struct IdPtrArray {
		DynArray<T*, ALLOC> list;

		typedef typename DynArray<T*, ALLOC>::iterator iterator;

		IdPtrArray() {}
		IdPtrArray(std::initializer_list<T> list) : list(list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i].id = i + 1;
			}
			this->list.insert(list.begin(), list.end(), this->list.begin());
		}
		IdPtrArray(DynArray<T> list) : list(list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i].id = i + 1;
			}
			this->list.insert(list.begin(), list.end(), this->list.begin());
		}
		~IdPtrArray() {
			free_backing_id_dynarray<T, ALLOC>(&list);
		}

		T* insert(T* ele) {
			for (size_t i = 0; i < list.size(); i++) {
				if (!list[i]) {
					ele->id = i + 1;
					list[i] = ele;
					return list[i];
				}
			}
			ele->id = list.size() + 1;
			list.push_back(ele);
			return list.back();
		}
		auto begin() -> decltype (list.begin()) {
			return list.begin();
		}
		auto end() -> decltype (list.end()) {
			return list.end();
		}
		auto size() -> decltype (list.size()) {
			return list.size();
		}
		auto back() -> decltype (list.back()) {
			return list.back();
		}
		iterator erase(iterator it) {
			(*it) = nullptr;
			return ++it;
		}
		T* remove(u32 id) {
			T* ptr = get(id);
			list[id - 1] = nullptr;
			return ptr;
		}
		T* get(u32 id) {
			return id && id <= list.size() ? list[id - 1] : nullptr;
		}
		T* operator[] (u32 id) {
			return get(id);
		}
		void clear() {
			list.clear();
		}
	};
	template<typename T, typename ALLOC>
	struct UIdPtrArray {
		IdGenerator gen;
		DynArray<T*, ALLOC> list;

		typedef typename DynArray<T*, ALLOC>::iterator iterator;

		UIdPtrArray() {}
		UIdPtrArray(std::initializer_list<T*> list) : list(list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i]->id = pack_handle(i + 1, gen.next());
			}
			this->list.insert(list.begin(), list.end(), this->list.begin());
		}
		UIdPtrArray(DynArray<T*> list) : list(list) {
			for (size_t i = 0; i < list.size(); i++) {
				list[i]->id = pack_handle(i + 1, gen.next());
			}
			this->list.insert(list.begin(), list.end(), this->list.begin());
		}
		~UIdPtrArray() {
			free_backing_id_dynarray<T, ALLOC>(&list);
		}

		T* insert(T* ele) {
			for (size_t i = 0; i < list.size(); i++) {
				if (!list[i]->id) {
					ele->id = pack_handle(i + 1, gen.next());
					list[i] = ele;
					return list[i];
				}
			}
			ele->id = pack_handle(list.size() + 1, gen.next());
			list.push_back(ele);
			return list.back();
		}
		auto begin() -> decltype (list.begin()) {
			return list.begin();
		}
		auto end() -> decltype (list.end()) {
			return list.end();
		}
		auto size() -> decltype (list.size()) {
			return list.size();
		}
		auto back() -> decltype (list.back()) {
			return list.back();
		}
		iterator erase(iterator it) {
			(*it)->id = 0;
			return ++it;
		}
		T* get(u64 handle) {
			u32 id = unpack_id_from_handle(handle);
			T* ptr = get(id);
			return ptr && ptr->id == handle ? ptr : nullptr;
		}
		T* get(u32 id) {
			return id && id <= list.size() ? list[id - 1] : nullptr;
		}
		void remove(u64 handle) {
			T* ptr = get(handle);
			if (ptr) ptr->id = 0;
		}
		T* operator[] (u32 id) {
			return get(id);
		}
		void clear() {
			list.clear();
		}
	};

}