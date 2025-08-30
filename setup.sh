#!/bin/bash
set -euo pipefail


# Configuration
STACK_VERSION=${STACK_VERSION:-8.12.0}
ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme}
CLUSTER_NAME=${CLUSTER_NAME:-es-docker-cluster}
#KIBANA_TOKEN=${KIBANA_TOKEN:-AAEAAWVsYXN0aWMva2liYW5hL215LWtpYmFuYS10b2tlbjoxZWdoS2gxLVFWaWNzZ0ZNd0FyVmRB}
KIBANA_ENCRYPTION_KEY=${KIBANA_ENCRYPTION_KEY:-5e7ccbdd01f6ec2c368020de79a5a5340a8908f35eb84d044778d9ab2ea70dd6}
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

# Génération des certificats Kibana
echo "Génération des certificats spécifiques pour Kibana..."
openssl genrsa -out kibana-key.pem 4096
openssl req -new -key kibana-key.pem -out kibana-req.pem \
  -subj "/C=MA/ST=Casablanca/L=Casablanca/O=ELK/CN=kibana"
openssl x509 -req -in kibana-req.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out kibana-cert.pem -days 365 \
  -extensions v3_req -extfile server-extensions.cnf

# Copie des certificats Kibana
cp kibana-cert.pem kibana/kibana.crt
cp kibana-key.pem kibana/kibana.key


# Génération des certificats Logstash
echo "Génération des certificats spécifiques pour Logstash..."
openssl genrsa -out logstash-key.pem 4096
openssl req -new -key logstash-key.pem -out logstash-req.pem \
  -subj "/C=MA/ST=Casablanca/L=Casablanca/O=ELK/CN=logstash"
openssl x509 -req -in logstash-req.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out logstash-cert.pem -days 365 \
  -extensions v3_req -extfile server-extensions.cnf

# Copie des certificats Kibana
cp kibana-cert.pem kibana/kibana.crt
cp kibana-key.pem kibana/kibana.key
cp logstash-cert.pem logstash/logstash.crt
cp logstash-key.pem logstash/logstash.key

# Services
for service in elasticsearch apm-server filebeat metricbeat; do
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
chmod 644 */ca.crt */*.crt 
chmod 600 */*.key
chmod 600 ca/ca.key
rm -f kibana-*.pem logstash-*.pem

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
echo "🧪 Test de validation du certificat pour Elasticsrearch :"
if openssl verify -CAfile certs/ca/ca.crt certs/elasticsearch/elasticsearch.crt; then
    echo "✅ Certificat valide !"
else
    echo "❌ Problème avec le certificat"
    exit 1
fi

echo "🧪 Test de validation du certificat pour Kibana :"
if openssl verify -CAfile certs/ca/ca.crt certs/kibana/kibana.crt; then
    echo "✅ Certificat valide !"
else
    echo "❌ Problème avec le certificat"
    exit 1
fi

echo "🧪 Test de validation du certificat pour Logstash :"
if openssl verify -CAfile certs/ca/ca.crt certs/logstash/logstash.crt; then
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
KIBANA_ENCRYPTION_KEY=$KIBANA_ENCRYPTION_KEY
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
      - xpack.security.authc.token.enabled=true
      - xpack.security.authc.api_key.enabled=true
      - xpack.security.enrollment.enabled=true
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
  

  token-generator:
    image: docker.elastic.co/elasticsearch/elasticsearch:${STACK_VERSION}
    container_name: token
    depends_on:
      elasticsearch:
        condition: service_healthy
    volumes:
      - ./generate-token.sh:/generate-token.sh
      - ./tokens:/usr/tokens
      - ./certs/ca/ca.crt:/usr/share/elasticsearch/config/certs/ca.crt:ro
      - ./certs/elasticsearch/elasticsearch.crt:/usr/share/elasticsearch/config/certs/elasticsearch.crt:ro
      - ./certs/elasticsearch/elasticsearch.key:/usr/share/elasticsearch/config/certs/elasticsearch.key:ro
    command: ["/bin/bash", "/generate-token.sh"]
    networks:
      - elk
    environment:
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
     # - KIBANA_TOKEN=\${KIBANA_TOKEN}

  kibana:
    image: docker.elastic.co/kibana/kibana:\${STACK_VERSION}
    container_name: kibana
    depends_on:
      elasticsearch:
        condition: service_healthy
    

    environment:
      - NODE_OPTIONS=--openssl-legacy-provider

      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTIC_PASSWORD=\${ELASTIC_PASSWORD}
      - KIBANA_TOKEN=\${KIBANA_TOKEN}
      - KIBANA_ENCRYPTION_KEY=\${KIBANA_ENCRYPTION_KEY}
      - ELASTICSEARCH_SERVICEACCOUNTTOKEN_FILE=/usr/tokens/kibana-token.txt

      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=/usr/share/kibana/config/certs/ca/ca.crt

      - SERVER_SSL_ENABLED=true

      - SERVER_SSL_CERTIFICATE=/usr/share/kibana/config/certs/kibana/kibana.crt

      - SERVER_SSL_KEY=/usr/share/kibana/config/certs/kibana/kibana.key

      - SERVER_SSL_CERTIFICATEAUTHORITIES=/usr/share/kibana/config/certs/ca/ca.crt

      - SERVER_HOST=0.0.0.0

      - SERVER_PORT=5601

      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=\${KIBANA_ENCRYPTION_KEY}

      - XPACK_REPORTING_ENCRYPTIONKEY=\${KIBANA_ENCRYPTION_KEY}

      - XPACK_SECURITY_ENCRYPTIONKEY=\${KIBANA_ENCRYPTION_KEY}

      - LOGGING_ROOT_LEVEL=debug
    volumes:
      - ./tokens:/usr/tokens:ro
      - ./certs:/usr/share/kibana/config/certs:ro
      - kibanadata:/usr/share/kibana/data
      - ./config/kibana.yml:/usr/share/kibana/config/kibana.yml 

    ports:
      - \${KIBANA_PORT}:5601
    networks:
      - elk
    healthcheck:
      test: ["CMD-SHELL", "curl -s -I -k https://localhost:5601/api/status | grep -q '200 OK'"]
      interval: 10s
      timeout: 10s
      retries: 120

  logstash:
    image: docker.elastic.co/logstash/logstash:\${STACK_VERSION}
    container_name: logstash
    depends_on:
      elasticsearch:
        condition: service_healthy
    environment:
      - NODE_NAME=logstash
      - XPACK_MONITORING_ENABLED=false
      - PIPELINE_WORKERS=1
      - PIPELINE_BATCH_SIZE=125
      - PIPELINE_BATCH_DELAY=50
      - LS_JAVA_OPTS=-Xmx1g -Xms1g
      - ELASTIC_PASSWORD=\${ELASTIC_PASSWORD}
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
    volumes:
      - ./certs:/usr/share/logstash/config/certs:ro
      - ./pipeline:/usr/share/logstash/pipeline:ro
      - logstashdata:/usr/share/logstash/data
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
      - "9600:9600"
    networks:
      - elk
    healthcheck:
      test: ["CMD-SHELL", "curl -s -f http://localhost:9600/_node/stats || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  esdata:
    driver: local
  kibanadata:
    driver: local
  logstashdata:
    driver: local

networks:
  elk:
    driver: bridge
EOF

echo "✅ Fichier docker-compose.yml créé"

# Créer le pipeline de base pour Logstash avec certificats spécifiques
cat > pipeline/logstash.conf <<'EOF'
input {
  beats {
    port => 5044
  }

  tcp {
    port => 5000
    codec => json_lines
  }
}

filter {
  mutate {
    add_field => { "processed_by" => "logstash" }
    add_field => { "processed_at" => "%{[@timestamp]}" }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    # Configuration SSL simplifiée - seulement vérification du serveur
    ssl_enabled => true
    ssl_certificate_authorities => "/usr/share/logstash/config/certs/ca/ca.crt"
    ssl_verification_mode => "full"
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
    index => "logstash-%{+YYYY.MM.dd}"
  }
}

EOF


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

xpack.security.enrollment.enabled: true

# Configuration réseau
transport.port: 9300
http.port: 9200
EOF


# Chemin du fichier token

TOKEN_FILE="tokens/kibana-token.txt"

# 1. Vérifier que le fichier existe
if [ ! -f "$TOKEN_FILE" ]; then
  echo "ERREUR : Fichier $TOKEN_FILE introuvable" >&2
  exit 1
fi

# 2. Lire le contenu directement
KIBANA_TOKEN=$(cat "$TOKEN_FILE")

# 3. Vérifier que le token n'est pas vide
if [ -z "$KIBANA_TOKEN" ]; then
  echo "ERREUR : Le fichier token est vide" >&2
  exit 1
fi

# 4. Utilisation exemple
echo "Token Kibana : ${KIBANA_TOKEN}"
echo "Clé de Kibana: ${KIBANA_ENCRYPTION_KEY}"



cat > config/kibana.yml <<EOF
# Configuration SSL pour Kibana
server.host: "0.0.0.0"
server.port: 5601

# SSL (HTTPS)
server.ssl:
  enabled: true
  certificate: /usr/share/kibana/config/certs/kibana/kibana.crt
  key: /usr/share/kibana/config/certs/kibana/kibana.key
  certificateAuthorities: ["/usr/share/kibana/config/certs/ca/ca.crt"]

# Connexion à Elasticsearch
elasticsearch.hosts: ["https://elasticsearch:9200"]
elasticsearch.ssl:
  certificateAuthorities: ["/usr/share/kibana/config/certs/ca/ca.crt"]
  verificationMode: "full"

# Authentification par Token de Service (obligatoire en 8.12.0)
elasticsearch.serviceAccountToken: "${KIBANA_TOKEN}"

# Clés de chiffrement (32 caractères minimum)
xpack.security.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"
xpack.encryptedSavedObjects.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"
xpack.reporting.encryptionKey: "${KIBANA_ENCRYPTION_KEY}"

# Logging
logging.appenders:
  default:
    type: console
    layout:
      type: json
logging.root.level: info

EOF


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


