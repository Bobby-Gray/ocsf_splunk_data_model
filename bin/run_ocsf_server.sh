#!/bin/sh
set -e

OCSF_DIR=$PWD/ocsf

mkdir -p $OCSF_DIR

rm -rf $OCSF_DIR/dev-ext || true && git clone https://github.com/ocsf/dev-ext.git $OCSF_DIR/dev-ext
rm -rf $OCSF_DIR/ocsf-schema || true && git clone https://github.com/ocsf/ocsf-schema.git $OCSF_DIR/ocsf-schema
rm -rf $OCSF_DIR/ocsf-server || true && git clone https://github.com/ocsf/ocsf-server.git $OCSF_DIR/ocsf-server

cd $OCSF_DIR/ocsf-server && docker build -t ocsf-server .

docker run \
	-it \
	--rm \
	--volume $OCSF_DIR/ocsf-schema:/app/schema \
	--volume $OCSF_DIR/dev-ext:/app/extension \
	-e SCHEMA_EXTENSION="/app/extension" \
	-p 8080:8080 \
	-p 8000:8000 \
	-p 8443:8443 \
	ocsf-server
