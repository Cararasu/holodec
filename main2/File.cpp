#include "pch.h"

#include "Header.h"
#include "File.h"

#include <stdio.h>
#include <stdlib.h>

namespace holodec {


	FileData read_file(const char* filename) {
		FILE *f = fopen(filename, "rb");
		fseek(f, 0, SEEK_END);
		long size = ftell(f);
		fseek(f, 0, SEEK_SET);

		char *data = (char*)malloc(size + 1);
		fread(data, size, 1, f);
		fclose(f);

		data[size] = 0;
		return { data, 0, (holodec::u64)size };
	}

	bool parse_line(FileData* fdata, Line* line, bool is_value) {
		line->line = { fdata->current_ptr(), 0 };
		line->offset = fdata->offset;
		line->indent = fdata->whitespaces();
		line->valuetoken = false;

		line->value = { nullptr, 0 };
		line->token = { nullptr, 0 };

		if (!is_value && fdata->token(&line->token)) {
			fdata->whitespaces();

			if (fdata->character(';')) {//immediate value
				line->valuetoken = true;
				fdata->whitespaces();

				if (fdata->line_until('%', &line->value)) {//comment
					fdata->remainingline();
				}
			}
			else {
				if (!fdata->newline()) {
					fdata->go_back(line->offset);//backtrack and parse a value
					if (fdata->line_until('%', &line->value)) {//comment
						fdata->remainingline();
					}
				}
			}
		}
		else {//no token
			if (fdata->character('%')) {
				fdata->remainingline();
			}
			else if (!fdata->newline()) {
				if (fdata->line_until('%', &line->value)) {//comment
					fdata->remainingline();
				}
			}
		}
		line->line.size = fdata->offset - line->offset;
		return true;
	}

	bool get_next_line(FileData* fdata, Line* line, bool is_value) {
		while (!fdata->eof()) {
			if (parse_line(fdata, line, is_value)) {
				if (line->token || line->value) return true;
			}
			else {
				return false;
			}
		}
		return false;
	}


	bool parse_unknown_token(DecompContext* context, FileData* fdata, Line* line, void* data) {
		if (line->token && line->value) printf("Unknown Token |%*c %.*s; %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr, (int)line->value.size, line->value.ptr);
		else if (line->token && line->valuetoken) printf("Unknown Token |%*c %.*s;\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
		else if (line->token) printf("Unknown Token |%*c %.*s\n", (int)line->indent, ' ', (int)line->token.size, line->token.ptr);
		else if (line->value) printf("Unknown Value |%*c %.*s\n", (int)line->indent, ' ', (int)line->value.size, line->value.ptr);
		if (line->token) return parse_token_args<void>(context, fdata, parse_unknown_token, nullptr, line);
		return true;
	}

}
