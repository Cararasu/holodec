#pragma once

#include "Header.h"
#include <map>
#include <unordered_map>

namespace holodec {

	struct Allocator {
		void* (*allocate)(size_t size, size_t alignment);
		void* (*reallocate)(void* data, size_t size, size_t alignment);
		void(*free)(void* data);
	};

	extern Allocator nop_allocator;

	template<typename T>
	inline T* t_allocate(Allocator* allocator, size_t count) {
		if (allocator) return reinterpret_cast<T*> (allocator->allocate(count * sizeof(T), alignof (T)));
		else return reinterpret_cast<T*> (malloc(count * sizeof(T)));
	}
	template<typename T>
	inline T* t_reallocate(Allocator* allocator, T* old_ptr, size_t count) {
		if (allocator) return reinterpret_cast<T*> (allocator->reallocate(old_ptr, count * sizeof(T), alignof (T)));
		else return reinterpret_cast<T*> (realloc(old_ptr, count * sizeof(T)));
	}
	template<typename T>
	inline void t_free(Allocator* allocator, T* ptr) {
		if (allocator) allocator->free(ptr);
		else free(ptr);
	}

	template<typename T>
	struct Array;
	template<typename T>
	struct DynArray;
	template<typename T, u32 LOCALSIZE = 4>
	struct StaticDynArray;
	template<typename T>
	struct IdArray;
	template<typename T>
	struct IdPtrArray;
	template<typename T>
	struct UIdArray;
	template<typename T>
	struct UIdPtrArray;

	template<typename S, typename T>
	using Map = std::map<S, T>;

	template<typename S, typename T>
	using MultiMap = std::unordered_multimap<S, T>;

	template<typename T>
	struct Array {

		size_t size = 0;
		T* data = nullptr;
		Allocator* allocator = nullptr;

		typedef T* iterator;

		void free() {
			if (data) {
				for (size_t i = 0; i < size; i++) {
					data[i].~T();
					t_free<T>(allocator, data);
				}
				size = 0;
				data = nullptr;
			}
		}

		Array(Allocator* allocator = nullptr) : size(0), data(nullptr), allocator(allocator) {}

		Array(size_t size, Allocator* allocator) : size(size), data(nullptr), allocator(allocator) {
			if (size) {
				data = t_allocate<T>(allocator, size);
				for (int i = 0; i < size; i++) {
					new (&data[i]) T;
				}
			}
		}
		Array(size_t size, const T& ele, Allocator* allocator) : size(size), data(nullptr), allocator(allocator) {
			if (size) {
				data = t_allocate<T>(allocator, size);
				for (size_t i = 0; i < size; i++) {
					new (&data[i]) T(ele);
				}
			}
		}
		Array(const Array<T>& array) : size(array.size), data(nullptr), allocator(array.allocator) {
			if (size) {
				data = t_allocate<T>(allocator, size);
				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(array.data[i]);
				}
			}
		}
		Array(const Array<T>&& array) : size(array.size), data(array.data), allocator(array.allocator) {
			array.size = 0;
			array.data = nullptr;
		}
		Array<T>& operator= (const std::initializer_list<T> init_list) {
			free();
			size = init_list.size();
			if (size) {
				data = t_allocate<T>(allocator, size);

				for (int i = 0; i < init_list.size(); i++) {
					new (&data[i]) T(init_list[i]);
				}
			}
			return *this;
		}
		Array<T>& operator= (const Array<T>& array) {
			free();
			data = nullptr;
			size = array.size;
			if (size) {
				data = t_allocate<T>(allocator, size);

				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(std::move(array[i]));
					i++;
				}
			}
			return *this;
		}
		Array<T>& operator= (Array<T>&& array) {
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
			data = t_reallocate<T>(allocator, data, size);
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

	template<typename T> 
	struct DynArray {

		size_t size = 0, capacity = 0;
		T* data = nullptr;
		Allocator* allocator = nullptr;

		typedef T* iterator;

		void free() {
			if (data) {
				for (size_t i = 0; i < size; i++) {
					data[i].~T();
				}
				t_free<T>(allocator, data);
				size = 0;
				capacity = 0;
				data = nullptr;
			}
		}

		DynArray(Allocator* allocator = nullptr) : size(0), capacity(0), data(nullptr), allocator(allocator) {}

		DynArray(size_t size, Allocator* allocator) : size(size), capacity(0), data(nullptr), allocator(allocator) {
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);
				for (int i = 0; i < size; i++) {
					new (&data[i]) T;
				}
			}
		}
		DynArray(size_t size, size_t capacity, Allocator* allocator) : size(size), capacity(capacity), data(nullptr), allocator(allocator) {
			if (size || capacity) {
				while (capacity < size) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);
				for (int i = 0; i < size; i++) {
					new (&data[i]) T;
				}
			}
		}
		DynArray(size_t size, const T& ele, Allocator* allocator) : size(size), capacity(8), data(nullptr), allocator(allocator) {
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);
				for (size_t i = 0; i < size; i++) {
					new (&data[i]) T(ele);
				}
			}

		}
		DynArray(const DynArray<T>& array) : size(array.size), capacity(array.capacity), data(nullptr), allocator(array.allocator) {
			if (size) {
				data = t_allocate<T>(allocator, capacity);
				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(array.data[i]);
				}
			}
		}
		DynArray(const DynArray<T>&& array) : size(array.size), capacity(array.capacity), data(array.data), allocator(array.allocator) {
			array.size = 0;
			array.capacity = 0;
			array.data = nullptr;
		}
		DynArray<T>& operator= (const std::initializer_list<T> init_list) {
			free();
			capacity = 0;
			size = init_list.size();
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);

				for (int i = 0; i < init_list.size(); i++) {
					new (&data[i]) T(init_list[i]);
				}
			}
			return *this;
		}
		DynArray<T>& operator= (const DynArray<T>& array) {
			free();
			data = nullptr;
			capacity = 0;
			size = array.size;
			if (size) {
				capacity = 8;
				while (capacity < size) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);

				for (int i = 0; i < array.size; i++) {
					new (&data[i]) T(array[i]);
					i++;
				}
			}
			return *this;
		}
		DynArray<T>& operator= (DynArray<T>&& array) {
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
				data = t_reallocate<T>(allocator, data, capacity);
			}
		}
		void shrink(size_t min_capacity = 0) {
			if (!size && !min_capacity) {
				t_free<T>(allocator, data);
				data = nullptr;
				capacity = 0;
			}
			else if (min_capacity > this->capacity) {
				capacity = MAX(capacity, 8);
				while (capacity < min_capacity) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
		}
		void push_back(T&& ele) {
			size_t neededcap = size + 1;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			new (&data[size++]) T(std::move(ele));
		}
		T* push_back(const T& ele) {
			size_t neededcap = size + 1;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			new (&data[size]) T(ele);
			return &data[size++];
		}
		void push_back(T&& ele, size_t count) {
			size_t neededcap = size + count;
			if (capacity < neededcap) {
				capacity = MAX(capacity, 8);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
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
				data = t_reallocate<T>(allocator, data, capacity);
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
				data = t_reallocate<T>(allocator, data, capacity);
			}
			new (&data[size]) T(std::forward<Args>(args)...);
			return &data[size++];
		}
		void pop_back(size_t count = 1) {
			data[--size].~T();
		}
		T& front() {
			return data[0];
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
				data = t_reallocate<T>(allocator, data, capacity);
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

	template<typename T, u32 LOCAL_SIZE>
	struct StaticDynArray {

		size_t size = 0, capacity = 0;
		T* data = nullptr;
		Allocator* allocator = nullptr;
		T localarr[LOCAL_SIZE];


		T* get(size_t i) {
			return i < LOCAL_SIZE ? &localarr[i] : &data[i - LOCAL_SIZE];
		}
		void free() {
			for (size_t i = 0; i < size; i++) {
				get(i)->~T();
			}
			if (data) {
				t_free<T>(allocator, data);
				size = 0;
				capacity = 0;
				data = nullptr;
			}
		}

		StaticDynArray(Allocator* allocator = nullptr) : size(0), capacity(0), data(nullptr), allocator(allocator) {}

		StaticDynArray(const StaticDynArray<T, LOCAL_SIZE>& array) : size(array.size), capacity(array.capacity), data(nullptr), allocator(array.allocator) {
			if (size > LOCAL_SIZE) {
				size_t needed_cap = size - LOCAL_SIZE;
				capacity = MAX(capacity, LOCAL_SIZE);
				while (capacity < needed_cap) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);
			}
			for (int i = 0; i < array.size; i++) {
				new (get(i)) T(array[i]);
			}
		}
		StaticDynArray(const StaticDynArray<T, LOCAL_SIZE>&& array) : size(array.size), capacity(array.capacity), data(array.data), allocator(array.allocator) {
			memcpy(localarr, array.localarr, LOCAL_SIZE * sizeof(T));

			array.size = 0;
			array.capacity = 0;
			array.data = nullptr;
		}
		StaticDynArray<T, LOCAL_SIZE>& operator= (const std::initializer_list<T> init_list) {
			free();

			capacity = 0;
			size = init_list.size();
			if (size > LOCAL_SIZE) {
				size_t needed_cap = size - LOCAL_SIZE;
				capacity = MAX(capacity, LOCAL_SIZE);
				while (capacity < needed_cap) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);
			}
			for (int i = 0; i < init_list.size(); i++) {
				new (get(i)) T(init_list[i]);
			}
			return *this;
		}
		StaticDynArray<T, LOCAL_SIZE>& operator= (const StaticDynArray<T, LOCAL_SIZE>& array) {
			free();

			data = nullptr;
			capacity = 0;
			size = array.size;
			if (size > LOCAL_SIZE) {
				size_t needed_cap = size - LOCAL_SIZE;
				capacity = MAX(capacity, LOCAL_SIZE);
				while (capacity < needed_cap) capacity *= 2;
				data = t_allocate<T>(allocator, capacity);
			}
			for (int i = 0; i < array.size; i++) {
				new (get(i)) T(array[i]);
			}
			return *this;
		}
		StaticDynArray<T, LOCAL_SIZE>& operator= (StaticDynArray<T, LOCAL_SIZE>&& array) {
			free();

			data = array.data;
			array.data = nullptr;
			memcpy(localarr, array.localarr, LOCAL_SIZE * sizeof(T));
			size = array.size;
			array.size = 0;
			capacity = array.capacity;
			array.capacity = 0;
			allocator = array.allocator;
			return *this;
		}
		~StaticDynArray() {
			free();
		}

		void shrink() {
			if (size < LOCAL_SIZE) {
				t_free<T>(allocator, data);
				data = nullptr;
				capacity = 0;
			}
			else if (4 > this->capacity) {
				size_t neededcap = LOCAL_SIZE;
				capacity = MAX(capacity, 4);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
		}
		void push_back(T&& ele) {
			size_t neededcap = size + 1;
			if (neededcap > LOCAL_SIZE && capacity < neededcap) {
				neededcap -= LOCAL_SIZE;
				capacity = MAX(capacity, 4);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			new (get(size)) T(std::move(ele));
		}
		T* push_back(T& ele) {
			size_t neededcap = size + 1;
			if (neededcap > LOCAL_SIZE && capacity < neededcap) {
				neededcap -= LOCAL_SIZE;
				capacity = MAX(capacity, 4);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			new (get(size)) T(ele);
			return get(size++);
		}
		void push_back(T&& ele, size_t count) {
			size_t neededcap = size + count;
			if (neededcap > LOCAL_SIZE && capacity < neededcap) {
				neededcap -= LOCAL_SIZE;
				capacity = MAX(capacity, 4);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			for (; size < neededcap; size++) {
				new (get(size)) T(ele);
			}
		}
		void push_back(T& ele, size_t count) {
			size_t neededcap = size + count;
			if (neededcap > LOCAL_SIZE && capacity < neededcap) {
				neededcap -= LOCAL_SIZE;
				capacity = MAX(capacity, 4);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			for (; size < neededcap; size++) {
				new (get(size)) T(ele);
			}
		}
		template< class... Args >
		T* emplace_back(Args&&... args) {
			size_t neededcap = size + 1;
			if (neededcap > LOCAL_SIZE && capacity < neededcap) {
				neededcap -= LOCAL_SIZE;
				capacity = MAX(capacity, 4);
				while (capacity < neededcap) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			new (get(size)) T(std::forward<Args>(args)...);
			return get(size++);
		}
		void pop_back(size_t count = 1) {
			get(--size)->~T();
		}
		T& front() {
			return *get(0);
		}
		T& back() {
			return *get(size - 1);
		}

		void clear() {
			for (size_t i = 0; i < size; i++) {
				get(i)->~T();
			}
			size = 0;
		}
		void resize(size_t size, const T& ele) {
			if (size > LOCAL_SIZE && size > (capacity - LOCAL_SIZE)) {
				capacity = MAX(capacity, 4);
				size_t needed = size - LOCAL_SIZE;
				while (capacity < needed) capacity *= 2;
				data = t_reallocate<T>(allocator, data, capacity);
			}
			for (size_t i = this->size; i < size; i++) {
				new (get(i)) T(ele);
			}
			this->size = size - LOCAL_SIZE;
		}

		T& operator[] (size_t i) {
			return *get(i);
		}
		const T& operator[] (size_t i) const {
			return *get(i);
		}

		struct iterator {
			StaticDynArray<T, LOCAL_SIZE>* arr;
			size_t index = 0;

			iterator(StaticDynArray<T, LOCAL_SIZE>* arr, size_t index) : arr(arr), index(index) {}
			iterator(const iterator& it) : arr(it.arr), index(it.index) {}
			iterator(iterator&& it) : arr(it.arr), index(it.index) {}
			iterator& operator=(iterator&& it) {
				this->arr = it.arr;
				this->index = it.index;
			}
			~iterator() {}


			T& operator[] (size_t i) {
				return *arr->get(index + i);
			}
			const T& operator[] (size_t i) const {
				return *arr->get(index + i);
			}
			T& operator->() {
				return *arr->get(index);
			}
			T& operator*() {
				return *arr->get(index);
			}
			bool operator<(iterator& it) {
				return index < it.index;
			}
			bool operator<=(iterator& it) {
				return index <= it.index;
			}
			bool operator>(iterator& it) {
				return index > it.index;
			}
			bool operator>=(iterator& it) {
				return index >= it.index;
			}
			bool operator==(iterator& it) {
				return index == it.index;
			}
			bool operator!=(iterator& it) {
				return index != it.index;
			}
			iterator operator+(size_t i) {
				return iterator(arr, index + i);
			}
			iterator operator-(size_t i) {
				return iterator(arr, index - i);
			}
			iterator& operator+=(size_t i) {
				index += i;
				return *this;
			}
			iterator& operator-=(size_t i) {
				index -= i;
				return *this;
			}
			T& operator++() {
				return *arr->get(++index);
			}
			T& operator--() {
				return *arr->get(--index);
			}
			T& operator++(int) {
				return *arr->get(index++);
			}
			T& operator--(int) {
				return *arr->get(index--);
			}
		};

		iterator begin() {
			return iterator(this, 0);
		}
		iterator end() {
			return iterator(this, size);
		}
		const iterator begin() const {
			return iterator(this, 0);
		}
		const iterator end() const {
			return iterator(this, size);
		}
	};

	template<typename T>
	inline void free_backing_id_dynarray(DynArray<T>* list) {
		if (list->data) {
			for (size_t i = 0; i < list->size; i++) {
				if (list->data[i].id) list->data[i].~T();
			}
			t_free<T>(list->allocator, list->data);
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
	template<typename T>
	struct IdArray {
		DynArray<T> list;
		typedef typename DynArray<T>::iterator iterator;


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
			free_backing_id_dynarray<T>(&list);
		}

		u32 insert(T&& ele) {
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
		u32 insert(const T& ele) {
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

	template<typename T>
	struct UIdArray {
		IdGenerator gen;
		DynArray<T> list;

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
			free_backing_id_dynarray<T>(&list);
		}

		u64 insert(T&& ele) {
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
		u64 insert(const T& ele) {
			for (size_t i = 0; i < list.size; i++) {
				if (!list[i].id) {
					list[i] = ele;
					list[i].id = pack_handle((u32)i + 1, gen.next());
					return list[i].id;
				}
			}
			list.push_back(ele);
			list.back().id = pack_handle((u32)list.size, gen.next());
			return list.back().id;
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

	template<typename T>
	struct IdPtrArray {
		DynArray<T*> list;

		typedef typename DynArray<T*>::iterator iterator;

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
			free_backing_id_dynarray<T>(&list);
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
	template<typename T>
	struct UIdPtrArray {
		IdGenerator gen;
		DynArray<T*> list;

		typedef typename DynArray<T*>::iterator iterator;

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
			free_backing_id_dynarray<T>(&list);
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