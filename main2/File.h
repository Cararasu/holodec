#pragma once

#include "Header.h"
#include "Array.h"
#include "String.h"


namespace holodec {

	struct Binary;


	struct DataPart {
		char* ptr;
		size_t size;

		operator bool() {
			return ptr != nullptr && size != 0;
		}
	};

	inline bool match_part(DataPart* token, const char* string, size_t size) {
		return size == token->size && strncmp(string, token->ptr, token->size) == 0;
	}
	inline bool match_part(DataPart* token, const char* string) {
		return match_part(token, string, strlen(string));
	}

	inline bool alpha(char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
	}
	inline bool numeric(char c) {
		return c >= '0' && c <= '9';
	}
	inline bool hex(char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	}
	inline bool lowercase(char c) {
		return c >= 'a' && c <= 'z';
	}
	inline bool uppercase(char c) {
		return c >= 'A' && c <= 'Z';
	}
	inline bool whitespace(char c) {
		return c == ' ' || c == '\t';
	}

	struct FileData {
		char* data;
		size_t offset;
		size_t size;

		char* current_ptr() {
			return &data[offset];
		}
		char peek() {
			return data[offset];
		}
		char pop_char() {
			return data[offset++];
		}
		void go_back(size_t offset) {
			this->offset = offset;
		}
		void pop(size_t n) {
			offset += n;
		}
		void push(size_t n) {
			offset -= n;
		}
		bool eof() {
			return offset >= size;
		}
		u32 whitespaces() {
			u32 n = 0;
			while (!eof()) {
				char c = pop_char();
				if (c == ' ') {
					n++;
				}
				else if (c == '\t') {
					n += 4;
				}
				else {
					push(1);
					break;
				}
			}
			return n;
		}
		bool character(char c) {
			if (eof()) return false;
			if (peek() == c) {
				offset++;
				return true;
			}
			return false;
		}
		bool alpha(char* c) {
			if (eof()) return false;
			*c = pop_char();
			if (holodec::alpha(*c)) return true;
			offset--;
			return false;
		}
		bool numeric(char* c) {
			if (eof()) return false;
			*c = pop_char();
			if (holodec::numeric(*c)) return true;
			offset--;
			return false;
		}
		bool newline() {
			if (eof()) return false;
			char c = pop_char();
			if (c == '\r') {
				c = pop_char();//handle \r\n
				if (c != '\n') offset--;
				return true;
			}
			else if (c == '\n') {
				return true;
			}
			offset--;
			return false;
		}
		void remainingline() {
			while (!eof() && !newline()) pop(1);
		}

		bool token(DataPart* token) {
			token->ptr = current_ptr();
			size_t base_offset = offset;
			char c = peek();
			if (holodec::alpha(c)) {
				while (holodec::alpha(c) || holodec::numeric(c)) {
					pop_char();
					c = peek();
				}
				token->size = offset - base_offset;
				return true;
			}
			return false;
		}
		bool line_until(char c, DataPart* line) {
			whitespaces();//trim start
			line->ptr = current_ptr();
			line->size = 0;
			while (true) {
				if (eof() || newline()) {
					return false;
				}
				if (c == pop_char()) {
					//trim end
					while (line->size && holodec::whitespace(line->ptr[line->size - 1]))
						line->size--;
					return true;
				}
				line->size++;
			}
		}
		bool integer(u64* i) {
			size_t savepoint = offset;
			*i = 0;
			u64 base;
			if (character('0') && character('x')) {
				base = 16;
			}
			else {
				go_back(savepoint);
				base = 10;
			}
			if (eof()) {
				go_back(savepoint);
				return false;
			}
			if (base == 16) {
				if (!holodec::hex(peek())) {
					go_back(savepoint);
					return false;
				}
				while (!eof()) {
					char c = peek();
					if (holodec::numeric(c)) {
						*i *= 16;
						*i += c - '0';
					}
					else if (holodec::lowercase(c)) {
						*i *= 16;
						*i += c - 'a';
					}
					else if (holodec::uppercase(c)) {
						*i *= 16;
						*i += c - 'A';
					}
					else break;
					pop_char();
				}
				return true;
			}
			else {
				if (!holodec::numeric(peek())) {
					go_back(savepoint);
					return false;
				}
				while (!eof()) {
					char c = peek();
					if (holodec::numeric(c)) {
						*i *= 10;
						*i += c - '0';
					}
					else break;
					pop_char();
				}
				return true;
			}
			go_back(savepoint);
			return false;
		}
		bool signed_integer(s64* i) {
			size_t savepoint = offset;
			*i = 1;
			if (character('-')) {
				*i = -1;
				i++;
			}
			u64 ui;
			if (integer(&ui)) {
				*i *= ui;
				return true;
			}
			go_back(savepoint);
			return false;
		}
	};

	struct Line {
		size_t offset, indent;
		DataPart line;
		DataPart token;
		DataPart value;
		bool valuetoken;
	};

	struct Token {
		DataPart name;
		DynArray<Token> subtokens;
		DynArray<DataPart> values;
	};

	struct DecompContext;

	FileData read_file(const char* filename);
	
	bool parse_unknown_token(DecompContext* context, FileData* fdata, Line* line, void*);

	bool get_next_line(FileData* fdata, Line* line, bool is_value);

	template<typename T>
	using LINE_PARSER = bool(*)(DecompContext* context, FileData* fdata, Line* line, T* obj);

	template<typename T>
	bool parse_token_args(DecompContext* context, FileData* fdata, LINE_PARSER<T> line_parser, T* obj, Line* base_line) {
		bool firstline = true;
		size_t indent;
		Line line;
		while (!fdata->eof()) {
			if (get_next_line(fdata, &line, base_line ? base_line->valuetoken : false)) {
				if (!line.token && !line.value) {
					return false;
				}
				if (firstline) {
					indent = line.indent;
					if (base_line && indent <= base_line->indent) {
						fdata->go_back(line.offset);
						return true;
					}
					firstline = false;
				}
				else {
					if (line.indent != indent) {
						fdata->go_back(line.offset);
						return true;
					}
				}
				if (line_parser) line_parser(context, fdata, &line, obj);
			}
		}
		return true;
	}
}