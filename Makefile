.PHONY: clean All

All:
	@echo "----------Building project:[ VulkanTest - Debug Windows ]----------"
	@cd "E:\GNUProg\Vulkan" && "$(MAKE)" -f  "VulkanTest.mk"
clean:
	@echo "----------Cleaning project:[ VulkanTest - Debug Windows ]----------"
	@cd "E:\GNUProg\Vulkan" && "$(MAKE)" -f  "VulkanTest.mk" clean
