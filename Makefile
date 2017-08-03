
.phony: buld clean release

build:
	@rm -rf build dist
	@echo -n "Building package ... " ; \
	pyinstaller --onefile obfuscator.py > /dev/null 2>&1 ; \
	echo "\033[32mDone\033[0m"

clean:
	@rm -rf pyconceal-*

dist/obfuscator:
	make build

release: dist/obfuscator doc/README
	@bash release.sh
