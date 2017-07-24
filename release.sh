#!/bin/bash

release_folder="pyconceal${version}"
mkdir -p ${release_folder}
cp obfuscator.config dist/obfuscator ${release_folder}/
