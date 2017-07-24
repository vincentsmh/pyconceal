#!/bin/bash

function get_version()
{
  git tag | head -n 1
}

version="$(get_version)"
release_folder="pyconceal-${version}"
rm -rf ${release_folder}
mkdir -p ${release_folder}
cp obfuscator.config dist/obfuscator ${release_folder}/
