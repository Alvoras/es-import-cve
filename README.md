# es-import-cve
Import the CVE NVD databases from the NIST into an Elasticsearch instance.

Forked from https://github.com/joshbressers/cve-analysis. 

## Required
Intended for Elastisearch > 7.0.

Check the elasticsearch lib version in the requirements.txt file. The lib version must be the same as your running Elastic stack version.

Ex : `elasticsearch==7.5.1`

## Quickstart:
Use `get-cve.sh` to pull all the databases from 2002.

Use `import.py -f <nvdcve_data>` to import one data file.

Use `update-es.sh` to import all .json files with the default presets (no proxy, no auth, default Kibana URL http://localhost:9200).