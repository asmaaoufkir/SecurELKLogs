#!/bin/bash
set -e

echo "En attente d'Elasticsearch..."
until curl -s --cacert /usr/share/elasticsearch/config/certs/ca.crt \
             -u elastic:${ELASTIC_PASSWORD} \
             https://elasticsearch:9200/_cluster/health | grep -q '"status":"green\|yellow"'; do
  sleep 5
done

echo "Création du token de service Kibana..."
TOKEN_RESPONSE=$(curl -s --cacert /usr/share/elasticsearch/config/certs/ca.crt \
                     -u elastic:${ELASTIC_PASSWORD} \
                     -X POST \
                     -H "Content-Type: application/json" \
                     https://elasticsearch:9200/_security/service/elastic/kibana/credential/token/kibana-token)

# Extraction du token avec jq (à installer si absent)
KIBANA_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token.value')

if [ -z "$KIBANA_TOKEN" ]; then
    echo "❌ Erreur: Échec de la création du token"
    exit 1
fi

# Stockage du token pour Kibana
echo "$KIBANA_TOKEN" > /usr/tokens/kibana-token.txt
chmod 640 /usr/tokens/kibana-token.txt

echo "✅ Token généré avec succès : ${KIBANA_TOKEN:0:12}..."
