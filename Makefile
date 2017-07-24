
.phony: buld

build:
	rm -rf build dist
	pyinstaller --onefile obfuscator.py
