.PHONY: clean All

All:
	@echo "----------Building project:[ main - Debug VC17 ]----------"
	@cd "main" && "$(MAKE)" -f  "main.mk"
clean:
	@echo "----------Cleaning project:[ main - Debug VC17 ]----------"
	@cd "main" && "$(MAKE)" -f  "main.mk" clean
