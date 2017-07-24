
.phony: buld release

build:
	rm -rf build dist
	pyinstaller --onefile obfuscator.py

dist/obfuscator:
	make build

release: dist/obfuscator doc/README
	@bash release.sh
