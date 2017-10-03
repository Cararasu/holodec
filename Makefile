.PHONY: clean All

All:
	@echo "----------Building project:[ main - Debug Windows ]----------"
	@cd "main" && "$(MAKE)" -f  "main.mk"
clean:
	@echo "----------Cleaning project:[ main - Debug Windows ]----------"
	@cd "main" && "$(MAKE)" -f  "main.mk" clean
