.PHONY: clean All

All:
	@echo ----------Building project:[ visited - Debug ]----------
	@"mingw32-make.exe"  -j 1 -f "visited.mk"
clean:
	@echo ----------Cleaning project:[ visited - Debug ]----------
	@"mingw32-make.exe"  -j 1 -f "visited.mk" clean
