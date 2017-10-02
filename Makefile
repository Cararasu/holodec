.PHONY: clean All

All:
	@echo "----------Building project:[ main - Debug ]----------"
	@cd "main" && "$(MAKE)" -f  "main.mk"
clean:
	@echo "----------Cleaning project:[ main - Debug ]----------"
	@cd "main" && "$(MAKE)" -f  "main.mk" clean
