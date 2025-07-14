#!/bin/bash
set -e

echo "Waiting for Elasticsearch..."
until curl -s --cacert /usr/share/elasticsearch/config/certs/ca.crt \
             --cert /usr/share/elasticsearch/config/certs/elasticsearch.crt \
             --key /usr/share/elasticsearch/config/certs/elasticsearch.key \
             -u elastic:$ELASTIC_PASSWORD \
             https://elasticsearch:9200/_cluster/health; do
  sleep 5
done

echo "Creating service token..."

# Génère le token et extrait uniquement la partie token
bin/elasticsearch-service-tokens create elastic/kibana my-kibana-token | \
grep -oP '(?<=SERVICE_TOKEN elastic/kibana/my-kibana-token = ).*' > /usr/tokens/kibana-token.txt
cat /usr/tokens/kibana-token.txt
