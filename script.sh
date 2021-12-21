#! /bin/bash
for filename in ../tkey/packages/* ; do
    echo "installing $filename" || continue
    # ... install packed packages
    packagename="`ls ${filename}| grep tkey`"
    npm i "${filename}/${packagename}"
done