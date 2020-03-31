#!/bin/bash

mkdir data
cd data

now=`date +'%Y'`
for year in `seq -w 2002 $now`;
do
 wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$year.json.gz
done
find . -name '*.gz' -exec gunzip -f {} \;
