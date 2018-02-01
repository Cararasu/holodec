#ifndef HSTHING_H
#define HSTHING_H

#include <string.h>
#include <stdint.h>
#include <cstdlib>
#include <utility>
#include <iostream>

#if defined(_WIN32) || defined(_WIN64) 
	#define snprintf _snprintf_s 
	#define vsnprintf _vsnprintf 
	#define strcasecmp _stricmp 
	#define strncasecmp _strnicmp 
#endif

namespace holodec {


	class HString {
		uint64_t m_hash;
		std::string m_str;

		void doHash() {
			m_hash = 0;
			uint64_t val = 5381;
			for (int i = 0; m_str[i]; i++) val = (val * 33) ^ m_str[i];
			m_hash = val;
		}
	public:
		HString (const char* ptr = "") : m_hash (0) {
			if(!ptr)
				ptr = "";
			m_str = ptr;
			doHash();
		}
		HString (const HString& str) : m_hash (str.m_hash), m_str (str.m_str) {}

		uint64_t hash() const {
			return m_hash;
		}
		const std::string& str() const {
			return m_str;
		}
		const char* cstr() const {
			return m_str.c_str();
		}
		operator bool() const {
			return m_str.size();
		}
		bool operator!() const {
			return !m_str.size();
		}

		char operator[] (int i) const {
			return m_str[i];
		}
		void update(const char* name){
			m_str = name;
			doHash();
		}
		void update(HString name){
			m_hash = name.m_hash;
			m_str = name.m_str;
		}
		
		bool staertsWith (HString arg) {
			if(*this == arg)
				return true;
			return strncmp (m_str.c_str(), arg.cstr(), m_str.size()) == 0;
		}
		
		friend int64_t compare (const HString* lhs, const HString* rhs);
	};
	inline int64_t compare (const HString* lhs, const HString* rhs) {
		return lhs->m_hash == rhs->m_hash ? lhs->m_str.compare(rhs->m_str) : lhs->m_hash - rhs->m_hash;
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
