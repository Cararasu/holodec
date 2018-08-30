#ifndef HSPARSEIDLIST_H
#define HSPARSEIDLIST_H

#include <vector>
#include <functional>

#include "General.h"

namespace holodec {

	class HIdGenerator {
	private:
		HId val = 1;
	public:
		HId next() {
			return val++;
		}
		void clear() {
			val = 1;
		}
	};

/**
 * Needs id member and relabel function
 * 
 */
	template<typename T>
	struct HIdList {
		HIdGenerator gen;
		HList<T> list;
		
		typedef typename HList<T>::iterator iterator;

		HIdList() {}
		HIdList (std::initializer_list<T> list) : list (list) {
			relabel();
		}
		HIdList (HList<T> list) : list (list) {
			relabel();
		}

		HId push_back(T& ele) {
			ele.id = gen.next();
			list.push_back(ele);
			return ele.id;
		}
		template< class... Args >
		HId emplace_back(Args&&... args) {
			list.emplace_back(args...);
			list.back().id = gen.next();
			return list.back().id;
		}
		void relabel () {
			for (T& ele : list) {
				ele.id = gen.next();
			}
		}
		auto begin() -> decltype(list.begin()){
			return list.begin();
		}
		auto end() -> decltype(list.end()){
			return list.end();
		}
		auto size() -> decltype(list.size()){
			return list.size();
		}
		auto back() -> decltype(list.back()){
			return list.back();
		}
		iterator erase(iterator it){
			it->id = 0;
			return it;
		}
		constexpr T* get (HId id) {
			return id <= list.size() || list[id - 1].id ? &list[id - 1] : nullptr;
		}
		constexpr T& operator[] (HId id) {
			return *get(id);
		}
		void clear() {
			gen.clear();
			list.clear();
		}
	};
	template<typename T>
	struct HIdPtrList {
		HIdGenerator gen;
		HList<T> list;
		
		typedef typename HList<T>::iterator iterator;

		HIdPtrList() {}
		HIdPtrList (std::initializer_list<T> list) : list (list) {
			relabel();
		}
		HIdPtrList (HList<T> list) : list (list) {
			relabel();
		}
		
		HId push_back (T& ele) {
			ele->id = gen.next();
			list.push_back (ele);
			return ele->id;
		}
		void relabel () {
			for (T& ele : list) {
				ele->id = gen.next();
			}
		}
		auto begin() -> decltype(list.begin()){
			return list.begin();
		}
		auto end() -> decltype(list.end()){
			return list.end();
		}
		auto size() -> decltype(list.size()){
			return list.size();
		}
		auto back() -> decltype(list.back()){
			return list.back();
		}
		iterator erase(iterator it) {
			return list.erase(it);
		}
		T* get (HId id) {
			if(!id)
				return nullptr;
			size_t lowerbound = 0, upperbound = list.size();
			if (upperbound >= id) {//optimization for quick access
				T& val = list[id - 1];
				if (val->id == id) //quick return
					return &val;
			}
			
			while(lowerbound <= upperbound) {// binary seach
				size_t middle = lowerbound + ((upperbound - lowerbound) / 2);
				HId middleId = list[middle]->id;
				if(middleId == id)
					return &(list[middle]);
				if(middleId < id)
					lowerbound = middle + 1;
				else
					upperbound = middle - 1;
			}
			return nullptr;
		}
		T& operator[] (HId id) {
			return *get(id);
		}
		void clear() {
			gen.clear();
			list.clear();
		}
	};
	
	template<typename T>
	struct HUniqueList {
		HList<T> list;
		
		typedef typename HList<T>::iterator iterator;

		HUniqueList() {}
		HUniqueList (std::initializer_list<T> list) : list (list) {
		}
		HUniqueList (HList<T> list) : list (list) {
		}

		void insert(T& ele) {
			for (T& e : list)
				if (e == ele)
					return;
			list.push_back(ele);
		}
		void insert(const T&& ele) {
			for (T& e : list)
				if (e == ele)
					return;
			list.push_back(ele);
		}
		auto begin() -> decltype(list.begin()){
			return list.begin();
		}
		auto end() -> decltype(list.end()){
			return list.end();
		}
		auto size() -> decltype(list.size()){
			return list.size();
		}
		auto back() -> decltype(list.back()) {
			return list.back();
		}
		auto empty() -> decltype(list.empty()) {
			return list.empty();
		}
		iterator erase(iterator it) {
			return list.erase(it);
		}
		T& operator[] (HId id) {
			return list[id];
		}
		auto clear() -> decltype(list.clear()){
			list.clear();
		}

	};
	
	template<typename T>
	class HSparseIdList {
		typedef typename std::vector<T>::iterator iterator;
		typedef typename std::vector<T>::const_iterator const_iterator;
		
		void label(){
			for(size_t i = 0; i < list.size();++i){
				list[i].id = static_cast<HId>(i + 1);
			}
		}
	public:
		
		HList<T> list;
		
		HSparseIdList(){}
		~HSparseIdList(){}
		HSparseIdList (const std::initializer_list<T>& list) : list (list) {
			label();
			shrink();
		}
		HSparseIdList (const HSparseIdList<T>& list) : list (list.list) {
			label();
			shrink();
		}
		HSparseIdList (const HList<T>& list) : list (list) {
			label();
			shrink();
		}

		HId push_back (T& ele) {
			ele.id = static_cast<HId>(list.size()) + 1;
			list.push_back (ele);
			return ele.id;
		}
		void pop_back () {
			list.pop_back ();
		}
		void shrink (std::function<void (HId, HId)> replacer = nullptr) {
			auto fit = list.begin();
			auto rit = list.end() - 1;
			while(fit != rit){
				while(fit->id && fit < rit) ++fit;
				while(!rit->id && fit < rit) --rit;
				if(fit == rit) break;
				
				HId id = static_cast<HId>(std::distance(list.begin(), rit) + 1);
				HId newId = static_cast<HId>(std::distance(list.begin(), fit) + 1);
				if(replacer)
					replacer(id, newId);
				*fit = *rit;
				fit->id = newId;
				rit->id = 0;
			}
			if(fit->id)
				++fit;
			
			list.erase(fit, list.end());
			list.shrink_to_fit();
		}
		auto begin() -> decltype(list.begin()){
			return list.begin();
		}
		auto end() -> decltype(list.end()){
			return list.end();
		}
		auto size() -> decltype(list.size()){
			return list.size();
		}
		auto back() -> decltype(list.back()){
			return list.back();
		}
		iterator erase(iterator it){
			it->id = 0;
			return ++it;
		}
		iterator it_at (HId id) {
			return list.begin() + (id-1);
		}
		T* get (HId id) {
			return &list[id-1];
		}
		constexpr T& operator[] (HId id) {
			return list[id-1];
		}
		void clear() {
			list.clear();
		}
	};

}

#endif // HSPARSEIDLIST_H
