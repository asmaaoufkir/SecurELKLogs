#!/bin/bash
set -euo pipefail

# Configuration
STACK_VERSION=${STACK_VERSION:-8.12.0}
ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme}
CLUSTER_NAME=${CLUSTER_NAME:-es-docker-cluster}
KIBANA_TOKEN=${KIBANA_TOKEN:-AAEAAWVsYXN0aWMva2liYW5hL215LWtpYmFuYS10b2tlbjoxZWdoS2gxLVFWaWNzZ0ZNd0FyVmRB}

echo "🔐 Génération des certificats SSL pour ELK Stack (compatible Docker)..."
echo "Version: $STACK_VERSION"
echo "Cluster: $CLUSTER_NAME"
echo ""

# Nettoyage
rm -rf certs
mkdir -p certs
cd certs

# 1. Génération de l'AC (Autorité de Certification)
echo "Génération de l'autorité de certification..."
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca-cert.pem \
  -subj "/C=MA/ST=Casablanca/L=Casablanca/O=ELK/CN=ELK-CA"

# 2. Génération de la clé serveur
echo "Génération de la clé privée serveur..."
openssl genrsa -out server-key.pem 4096

# 3. Génération de la demande de certificat
echo "Génération de la demande de certificat..."
openssl req -new -key server-key.pem -out server-req.pem \
  -subj "/C=MA/ST=Casablanca/L=Casablanca/O=ELK/CN=elasticsearch"

# 4. Création du fichier de configuration pour les extensions
cat > server-extensions.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = elasticsearch
DNS.2 = localhost
DNS.3 = kibana
DNS.4 = logstash
DNS.5 = apm-server
DNS.6 = filebeat
DNS.7 = metricbeat
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# 5. Signature du certificat avec extensions
echo "Signature du certificat serveur..."
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 \
  -extensions v3_req -extfile server-extensions.cnf

# 6. Organisation pour ELK Stack
echo "Organisation des certificats..."
mkdir -p ca elasticsearch kibana logstash apm-server filebeat metricbeat

# CA
cp ca-cert.pem ca/ca.crt
cp ca-key.pem ca/ca.key

# Services
for service in elasticsearch kibana logstash apm-server filebeat metricbeat; do
    cp ca-cert.pem $service/ca.crt
    cp server-cert.pem $service/elasticsearch.crt
    cp server-key.pem $service/elasticsearch.key
done

# 7. Permissions spéciales pour Docker
echo "🐳 Configuration des permissions pour Docker..."
# Elasticsearch dans Docker s'exécute avec l'UID 1000
# Nous devons nous assurer que les fichiers sont lisibles par cet utilisateur

# Méthode compatible sans sudo
chmod -R 755 .
chmod 644 */ca.crt */elasticsearch.crt */elasticsearch.key
chmod 600 ca/ca.key

# Si nous avons les droits sudo, nous pouvons être plus précis
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    echo "🔐 Application des permissions propriétaires avec sudo..."
    sudo chown -R 1000:1000 .
else
    echo "ℹ️  Permissions de base appliquées. Si vous avez des problèmes, exécutez :"
    echo "   sudo chown -R 1000:1000 certs/"
fi

# 8. Nettoyage des fichiers temporaires
rm ca-cert.pem ca-key.pem server-*.pem server-extensions.cnf ca-cert.srl

cd ..

echo "✅ Certificats générés avec succès !"
echo ""
echo "📋 Structure finale :"
if command -v tree >/dev/null 2>&1; then
    tree certs
else
    find certs -type f -exec ls -la {} \;
fi

echo ""
echo "🔍 Vérification des permissions :"
ls -la certs/elasticsearch/

echo ""
echo "🔍 Vérification du certificat :"
openssl x509 -in certs/elasticsearch/elasticsearch.crt -noout -text | grep -A 15 "X509v3 Subject Alternative Name" || echo "Certificat généré (vérification SAN non disponible sur cette version d'OpenSSL)"

echo ""
echo "🧪 Test de validation du certificat :"
if openssl verify -CAfile certs/ca/ca.crt certs/elasticsearch/elasticsearch.crt; then
    echo "✅ Certificat valide !"
else
    echo "❌ Problème avec le certificat"
    exit 1
fi

echo ""
echo "🔑 Génération du fichier .env pour Docker Compose..."
cat > .env <<EOF
# Version de la Stack ELK
STACK_VERSION=$STACK_VERSION

# Mot de passe Elasticsearch
ELASTIC_PASSWORD=$ELASTIC_PASSWORD

# Configuration du cluster
CLUSTER_NAME=$CLUSTER_NAME
LICENSE=basic
MEM_LIMIT=1073741824

# Ports
ES_PORT=9200
KIBANA_PORT=5601
LOGSTASH_PORT=5044

# Configuration SSL
ELASTIC_SECURITY_ENABLED=true
KIBANA_SECURITY_ENABLED=true

# Configuration des certificats
CERTS_DIR=./certs

# Configuration réseau
ES_HOST=elasticsearch
KIBANA_HOST=kibana

# Configuration Docker
ELASTICSEARCH_UID=1000
ELASTICSEARCH_GID=1000
EOF

echo "✅ Fichier .env créé avec les paramètres par défaut"

echo ""
echo "🐳 Génération du docker-compose.yml compatible..."
cat > docker-compose.yml <<EOF

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:\${STACK_VERSION}
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=\${CLUSTER_NAME}
      - discovery.type=single-node
      - ELASTIC_PASSWORD=\${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.http.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.transport.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=\${LICENSE}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - ./certs:/usr/share/elasticsearch/config/certs:ro
      - esdata:/usr/share/elasticsearch/data
      - ./config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml 
    ports:
      - \${ES_PORT}:9200
    networks:
      - elk
    healthcheck:
      test: ["CMD-SHELL", "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication credentials'"]
      interval: 10s
      timeout: 10s
      retries: 120

  #token-generator:
  #  image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
  #  container_name: token
  #  depends_on:
  #    elasticsearch:
  #      condition: service_healthy
  #  volumes:
  #    - ./tokens:/usr/tokens
  #    - ./certs:/usr/share/elasticsearch/config/certs:ro
  #  #command: >
  #  #  bash -c "
  #  #    mkdir -p /usr/tokens &&
  #  #    sleep 15 &&
  #  #    echo 'Test de connexion à Elasticsearch...' &&
  #  #    until curl --cacert config/certs/ca.crt --cert config/certs/elasticsearch.crt --key config/certs/elasticsearch.key -u elastic:${ELASTIC_PASSWORD} -s https://elasticsearch:9200/_cluster/health; do  
  #  #      echo 'En attente Elasticsearch...'
  #  #      sleep 5
  #  #    done &&
  #  #    echo 'Génération du token...' &&
  #  #    bin/elasticsearch-service-tokens create elastic/kibana my-kibana-token > /usr/tokens/kibana-token.txt 2>&1 &&
  #  #    echo 'Token créé:' &&
  #  #    cat /usr/tokens/kibana-token.txt
  #  #  "

  #  command: >
  #    bash -c "
  #      set -e
  #      mkdir -p /usr/tokens
  #      sleep 15
  #      echo 'Test de connexion à Elasticsearch sur https://elasticsearch:9200...'
  #      
  #      # Test avec verbose pour debug
  #      curl --cacert config/certs/ca.crt --cert config/certs/elasticsearch.crt --key config/certs/elasticsearch.key -u elastic:${ELASTIC_PASSWORD} -v https://elasticsearch:9200/_cluster/health
  #      
  #      if [ $? -eq 0 ]; then
  #        echo 'Connexion réussie, génération du token...'
  #        bin/elasticsearch-service-tokens create elastic/kibana my-kibana-token > /usr/tokens/kibana-token.txt 2>&1
  #        echo 'Token créé:'
  #        cat /usr/tokens/kibana-token.txt
  #      else
  #        echo 'Échec de connexion à Elasticsearch'
  #        exit 1
  #      fi
  #    "
  
  token-generator:
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    container_name: token
    depends_on:
      elasticsearch:
        condition: service_healthy
    volumes:
      - ./tokens:/usr/tokens
      - ./certs/ca.crt:/tmp/ca.crt:ro
      - ./certs/elasticsearch/elasticsearch.crt:/tmp/elasticsearch.crt:ro
      - ./certs/elasticsearch/elasticsearch.key:/tmp/elasticsearch.key:ro
    command: >
      bash -c "
        mkdir -p /usr/tokens &&
        sleep 15 &&
        echo 'Test de connexion à Elasticsearch...' &&
        until curl --cacert /tmp/ca.crt --cert /tmp/elasticsearch.crt --key /tmp/elasticsearch.key -u elastic:${ELASTIC_PASSWORD} -s https://elasticsearch:9200/_cluster/health; do  
          echo 'En attente Elasticsearch...'
          sleep 5
        done &&
        echo 'Génération du token...' &&
        bin/elasticsearch-service-tokens create elastic/kibana my-kibana-token > /usr/tokens/kibana-token.txt 2>&1 &&
        echo 'Token créé:' &&
        cat /usr/tokens/kibana-token.txt
      "
    networks:
      - elk
    environment:
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}

  kibana:
    image: docker.elastic.co/kibana/kibana:\${STACK_VERSION}
    container_name: kibana
    depends_on:
      elasticsearch:
        condition: service_healthy
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      # Utiliser le token au lieu de username/password
     #- ELASTICSEARCH_SERVICEACCOUNTTOKEN=${KIBANA_TOKEN}
      - ELASTICSEARCH_SERVICEACCOUNTTOKEN_FILE=/tokens/kibana-token.txt      
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
      - SERVER_SSL_ENABLED=true
      - SERVER_SSL_CERTIFICATE=config/certs/kibana/elasticsearch.crt
      - SERVER_SSL_KEY=config/certs/kibana/elasticsearch.key
    volumes:
      - ./certs:/usr/share/kibana/config/certs:ro
      - kibanadata:/usr/share/kibana/data
      - ./tokens:/usr/share/kibana/config/tokens:ro
    ports:
      - \${KIBANA_PORT}:5601
    networks:
      - elk
    healthcheck:
      test: ["CMD-SHELL", "curl -s -I http://localhost:5601 | grep -q 'HTTP/1.1 302 Found'"]
      interval: 10s
      timeout: 10s
      retries: 120

volumes:
  esdata:
    driver: local
  kibanadata:
    driver: local

networks:
  elk:
    driver: bridge
EOF

echo "✅ Fichier docker-compose.yml créé"



# Configuration des fichiers YAML
cat > config/elasticsearch.yml <<EOF
cluster.name: "es-docker-cluster"
network.host: 0.0.0.0


# Configuration TLS
xpack.security.http.ssl:
  enabled: true
  certificate: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch.crt
  key: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch.key
  certificate_authorities: ["/usr/share/elasticsearch/config/certs/elasticsearch/ca.crt"]
  verification_mode: certificate

xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  certificate: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch.crt
  key: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch.key
  certificate_authorities: ["/usr/share/elasticsearch/config/certs/elasticsearch/ca.crt"]

# Configuration réseau
transport.port: 9300
http.port: 9200
EOF





echo ""
echo "📝 Prochaines étapes :"
echo "1. Lancez votre stack ELK avec: docker-compose up -d"
echo "2. Surveillez les logs avec: docker-compose logs -f"
echo "3. Accédez à Kibana: https://localhost:5601"
echo "   - Utilisateur: elastic"
echo "   - Mot de passe: $ELASTIC_PASSWORD"

echo ""
echo "🚨 En cas de problème de permissions, exécutez :"
echo "   sudo chown -R 1000:1000 certs/"
echo "   ou utilisez le script fix-permissions.sh"

echo ""
echo "🛡️  Sécurité :"
echo "- Les certificats sont valides pour 365 jours"
echo "- Changez le mot de passe par défaut en production"
echo "- SSL/TLS activé sur HTTP et Transport"
