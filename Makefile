.PHONY: clean All

All:
	@echo "----------Building project:[ def - Debug ]----------"
	@cd "def" && "$(MAKE)" -f  "def.mk"
clean:
	@echo "----------Cleaning project:[ def - Debug ]----------"
	@cd "def" && "$(MAKE)" -f  "def.mk" clean
