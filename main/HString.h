#ifndef HSTHING_H
#define HSTHING_H

#include <string.h>
#include <stdint.h>
#include <cstdlib>
#include <utility>
#include <iostream>

namespace holodec {


	class HString {
		uint64_t m_hash;
		const char * m_cstr;

		void doHash() {
			m_hash = 0;
			if (m_cstr == 0) return;
			uint64_t val = 5381;
			for (int i = 0; m_cstr[i]; i++) val = (val * 33) ^ m_cstr[i];
			m_hash = val;
		}
	public:
		HString() : m_hash (0), m_cstr (0) {}
		HString (const char* ptr) : m_hash (0), m_cstr (ptr) {
			doHash();
		}
		HString (const HString& str) : m_hash (str.m_hash), m_cstr (str.m_cstr) {}
		HString operator= (HString& str) {
			return HString (str);
		}
		HString operator= (const char* str) {
			return HString (str);
		}

		uint64_t hash() const {
			return m_hash;
		}
		const char* cstr() const {
			return m_cstr;
		}
		void update (const char* ptr) {
			m_cstr = ptr;
			doHash();
		}
		void update (HString str) {
			m_hash = str.m_hash;
			m_cstr = str.m_cstr;
		}
		operator bool() const {
			return m_cstr != nullptr;
		}
		bool operator!() const {
			return m_cstr == nullptr;
		}

		char operator[] (int i) const {
			return m_cstr[i];
		}
		void del(HString* str){
			if(m_cstr)
				free(const_cast<char*>(m_cstr));
			str->update(0);
		}
		HString copy(){
			return HString(strdup(m_cstr));
		}
		
		static HString create(const char* ptr){
			return HString(strdup(ptr));
		}
		static HString create(HString ptr){
			return ptr.copy();
		}
		
		friend int64_t compare (const HString* lhs, const HString* rhs);
	};
	inline int64_t compare (const HString* lhs, const HString* rhs) {
		return lhs->m_hash == rhs->m_hash ? (lhs->m_cstr == rhs->m_cstr ? 0 : strcmp (lhs->m_cstr, rhs->m_cstr)) : lhs->m_hash - rhs->m_hash;
	}
	inline bool operator== (const HString& lhs, const HString& rhs) {
		return compare (&lhs, &rhs) == 0;
	}
	inline bool operator< (const HString& lhs, const HString& rhs) {
		return compare (&lhs, &rhs) < 0;
	}
	inline bool operator<= (const HString& lhs, const HString& rhs) {
		return compare (&lhs, &rhs) <= 0;
	}
	inline bool operator> (const HString& lhs, const HString& rhs) {
		return compare (&lhs, &rhs) > 0;
	}
	inline bool operator>= (const HString& lhs, const HString& rhs) {
		return compare (&lhs, &rhs) >= 0;
	}
	inline bool caseCmpHString (HString lhs, HString rhs) {
		return strcasecmp (lhs.cstr(), rhs.cstr()) == 0;
	}
}

#endif // HSTHING_H
