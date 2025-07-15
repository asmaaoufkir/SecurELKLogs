#!/bin/bash

echo "🔍 Script de Dépannage ELK Stack"
echo "=================================="

# Vérifier si les conteneurs sont en cours d'exécution
echo "1. Vérification du statut des conteneurs..."
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(elasticsearch|kibana|token)"

echo ""
echo "2. Vérification de la santé d'Elasticsearch..."
curl -s --cacert certs/ca/ca.crt -u elastic:changeme https://localhost:9200/_cluster/health | jq '.' 2>/dev/null || echo "Elasticsearch ne répond pas ou jq n'est pas installé"

echo ""
echo "3. Vérification si l'index de sécurité existe..."
curl -s --cacert certs/ca/ca.crt -u elastic:changeme https://localhost:9200/_cat/indices/.security-* 2>/dev/null || echo "Index de sécurité non trouvé ou ES ne répond pas"

echo ""
echo "4. Vérification du fichier token..."
if [ -f "tokens/kibana-token.txt" ]; then
    echo "Le fichier token existe :"
    echo "Contenu: $(cat tokens/kibana-token.txt)"
    echo "Taille: $(stat -f%z tokens/kibana-token.txt 2>/dev/null || stat -c%s tokens/kibana-token.txt)"
else
    echo "Fichier token non trouvé"
fi

echo ""
echo "5. Test d'authentification avec le token..."
if [ -f "tokens/kibana-token.txt" ]; then
    TOKEN=$(cat tokens/kibana-token.txt)
    curl -s --cacert certs/ca/ca.crt -H "Authorization: Bearer $TOKEN" https://localhost:9200/ | jq '.cluster_name' 2>/dev/null || echo "Authentification par token échouée"
fi

echo ""
echo "6. Vérification des logs..."
echo "Logs Elasticsearch (20 dernières lignes):"
docker logs elasticsearch --tail 20

echo ""
echo "Logs Kibana (20 dernières lignes):"
docker logs kibana --tail 20

echo ""
echo "7. Vérification des permissions de fichiers..."
ls -la certs/elasticsearch/
ls -la certs/kibana/
ls -la tokens/ 2>/dev/null || echo "Répertoire tokens non trouvé"

echo ""
echo "8. Vérification des certificats..."
openssl verify -CAfile certs/ca/ca.crt certs/elasticsearch/elasticsearch.crt
openssl verify -CAfile certs/ca/ca.crt certs/kibana/kibana.crt
