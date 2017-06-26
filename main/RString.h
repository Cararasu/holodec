#ifndef RSTRING_H
#define RSTRING_H

#include <string.h>
#include <stdint.h>
#include <cstdlib>
#include <utility>
#include <iostream>

namespace holodec {


	class RString {
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
		RString() : m_hash (0), m_cstr (0) {}
		RString (const char* ptr) : m_hash (0), m_cstr (ptr) {
			doHash();
		}
		RString (const RString& str) : m_hash (str.m_hash), m_cstr (str.m_cstr) {}
		RString operator= (RString& str) {
			return RString (str);
		}
		RString operator= (const char* str) {
			return RString (str);
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
		void update (RString str) {
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
		
		static RString createNewString(const char* ptr){
			return RString(strdup(ptr));
		}
		static RString createNewString(RString ptr){
			return RString(strdup(ptr.cstr()));
		}
		static void destroyString(RString* str){
			free((void*)str->cstr());
			str->update(0);
		}
		
		friend int64_t compare (const RString* lhs, const RString* rhs);
	};
	inline int64_t compare (const RString* lhs, const RString* rhs) {
		return lhs->m_hash == rhs->m_hash ? (lhs->m_cstr == rhs->m_cstr ? 0 : strcmp (lhs->m_cstr, rhs->m_cstr)) : lhs->m_hash - rhs->m_hash;
	}
	inline bool operator== (const RString& lhs, const RString& rhs) {
		return compare (&lhs, &rhs) == 0;
	}
	inline bool operator< (const RString& lhs, const RString& rhs) {
		return compare (&lhs, &rhs) < 0;
	}
	inline bool operator<= (const RString& lhs, const RString& rhs) {
		return compare (&lhs, &rhs) <= 0;
	}
	inline bool operator> (const RString& lhs, const RString& rhs) {
		return compare (&lhs, &rhs) > 0;
	}
	inline bool operator>= (const RString& lhs, const RString& rhs) {
		return compare (&lhs, &rhs) >= 0;
	}
	inline bool caseCmpRString (RString lhs, RString rhs) {
		return strcasecmp (lhs.cstr(), rhs.cstr()) == 0;
	}
}

#endif // RSTRING_H
