#ifndef OUTPUT_H
#define OUTPUT_H


#include "HString.h"
#include <stdio.h>
#include <stdarg.h>

namespace holodec {

	enum class LogLevel {
		eTrace,
		eDebug,
		eInfo,
		eWarn,
		eError,
	};
	extern FILE * g_log_output;

	struct Logger {
		HString module_name;
		LogLevel level = LogLevel::eInfo;

		Logger (HString module_name) : module_name (module_name) {

		}
		~Logger() = default;

		template<LogLevel LL>
		void log (const char* fstring, ...) {
			if (LL >= level) {
				printf ("%s - ", module_name.cstr());
				va_list args;
				va_start (args, fstring);
				vfprintf (g_log_output, fstring, args);
				va_end (args);
				puts ("");
			}
		}
		template<LogLevel LL>
		void log_clean (const char* fstring, ...) {
			if (LL >= level) {
				va_list args;
				va_start (args, fstring);
				vfprintf (g_log_output, fstring, args);
				va_end (args);
				puts ("");
			}
		}
	};

	extern Logger g_logger;

	struct Console {
		Console() = default;
		~Console() = default;
		
		void print(const char* fstring, ...);
		
		void processInput();
		
		void processForever();
	};
	
	extern Console g_console; 

}

#endif // OUTPUT_H
