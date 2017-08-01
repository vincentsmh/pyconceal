
.phony: buld clean release

build:
	rm -rf build dist
	pyinstaller --onefile obfuscator.py

clean:
	@rm -rf pyconceal-*

dist/obfuscator:
	make build

release: dist/obfuscator doc/README
	@bash release.sh
