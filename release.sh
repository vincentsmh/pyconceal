#!/bin/bash

function get_version()
{
  git tag | tail -n 1
}

version="$(get_version)"
release_folder="pyconceal-${version}"
rm -rf ${release_folder}
mkdir -p ${release_folder}
cp obfuscator.config dist/obfuscator doc/README ${release_folder}/
tar zcvf ${release_folder}.tar.gz ${release_folder} > /dev/null
rm -rf ${release_folder} build dist
echo -e "Release package: ${release_folder}.tar.gz"
echo -e
