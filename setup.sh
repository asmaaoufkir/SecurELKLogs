#!/bin/bash
set -euo pipefail

# Vérification des dépendances
for cmd in docker docker-compose openssl unzip; do
  if ! command -v $cmd &> /dev/null; then
    echo "Erreur: $cmd n'est pas installé"
    exit 1
  fi
done



# Génération des mots de passe sécurisés
generate_password() {
  openssl rand -base64 24 | tr -d '\n=+/'
}

export ELASTIC_PASSWORD=$(generate_password)
export LOGSTASH_PASSWORD=$(generate_password)
export KIBANA_PASSWORD=$(generate_password)
export APM_PASSWORD=$(generate_password)


# Nettoyage complet
rm -rf certs
mkdir -p certs

# 1. Génération de l'AC (Autorité de Certification)
echo "🔐 Génération de l'AC..."
docker run -u root --rm -v $(pwd)/certs:/certs \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bin/elasticsearch-certutil ca --silent --pem --out /certs/ca.zip

unzip certs/ca.zip -d certs/

# 2. Génération des certificats
echo "🔐 Génération des certificats..."
docker run -u root --rm -v $(pwd)/certs:/certs \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 \
  bin/elasticsearch-certutil cert --silent --pem \
  --ca-cert /certs/ca/ca.crt --ca-key /certs/ca/ca.key \
  --name elasticsearch --dns localhost --ip 127.0.0.1 \
  --out /certs/certs.zip

# 3. Organisation correcte des fichiers
unzip certs/certs.zip -d certs/
mv certs/elasticsearch/* certs/
rmdir certs/elasticsearch
cp certs/ca/ca.crt certs/

# 4. Structure finale
mkdir -p certs/{elasticsearch,kibana,logstash,apm-server}
for service in elasticsearch kibana logstash apm-server; do
  cp certs/ca.crt certs/$service/
  cp certs/elasticsearch.crt certs/$service/
  cp certs/elasticsearch.key certs/$service/
done

# 5. Nettoyage
rm certs/ca.zip certs/certs.zip

# 6. Permissions
chmod -R 750 certs
chown -R 1000:1000 certs

echo "✅ Certificats générés avec succès !"
tree certs




# Configuration des fichiers YAML
cat > config/elasticsearch.yml <<EOF
cluster.name: "es-docker-cluster"
network.host: 0.0.0.0


# Configuration TLS
#xpack.security.http.ssl:
#  enabled: true
#  keystore.path: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch.p12
#  verification_mode: certificate
#
#xpack.security.transport.ssl:
#  enabled: true
#  verification_mode: certificate
#  keystore.path: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch.p12
#
#/usr/share/elasticsearch/config/certs

#certs
#├── ca
#│   ├── ca.crt
#│   └── ca.key
#├── ca.zip
#├── elasticsearch
#│   └── elasticsearch
#│       ├── elasticsearch.crt
#│       └── elasticsearch.key
#└── elasticsearch.zip
#

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

#xpack.security.http.ssl:
#  enabled: true
#  certificate: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch/elasticsearch.crt
#  key: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch/elasticsearch.key
#  certificate_authorities: [/usr/share/elasticsearch/config/certs/ca/ca.crt]
#
#xpack.security.transport.ssl:
#  enabled: true
#  verification_mode: certificate
#  certificate: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch/elasticsearch.crt
#  key: /usr/share/elasticsearch/config/certs/elasticsearch/elasticsearch/elasticsearch.key
#  certificate_authorities: [/usr/share/elasticsearch/config/certs/ca/ca.crt]
#
# Configuration sécurité
xpack.security.authc:
  api_key.enabled: true
  anonymous:
    authz_exception: false
    roles: monitoring_user

# Configuration réseau
transport.port: 9300
http.port: 9200
EOF

cat > config/kibana.yml <<EOF
server.host: "0.0.0.0"
server.publicBaseUrl: "https://localhost:5601"


server.ssl:
  enabled: true
  certificate: /usr/share/kibana/config/certs/kibana/kibana.crt
  key: /usr/share/kibana/config/certs/kibana/kibana.key

elasticsearch.hosts: ["https://elasticsearch:9200"]
elasticsearch.ssl:
  certificateAuthorities: /usr/share/kibana/config/certs/ca/ca.crt
  verificationMode: certificate

# Sécurité
xpack.security.encryptionKey: "$(generate_password)"
xpack.encryptedSavedObjects.encryptionKey: "$(generate_password)"
EOF

cat > config/apm-server.yml <<EOF
apm-server:
  host: "0.0.0.0:8200"
  ssl:
    certificate: /usr/share/apm-server/config/certs/apm-server/apm-server.crt
    key: /usr/share/apm-server/config/certs/apm-server/apm-server.key

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  ssl:
    certificate_authorities: /usr/share/apm-server/config/certs/ca/ca.crt
    verification_mode: certificate

# Configuration sécurité
apm-server.api_key.enabled: true
EOF

# Création des pipelines Logstash
cat > pipelines/logs-pipeline.conf <<EOF
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/usr/share/logstash/config/certs/logstash/logstash.crt"
    ssl_key => "/usr/share/logstash/config/certs/logstash/logstash.key"
  }
}

filter {
  # Parsing des logs
  grok {
    match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:log_level} %{DATA:source} - %{GREEDYDATA:log_message}" }
  }

  # Suppression des champs sensibles
  mutate {
    remove_field => ["agent", "ecs", "input", "tags"]
  }

  # Anonymisation des données sensibles
  fingerprint {
    source => ["source_ip"]
    target => "source_ip_anon"
    method => "SHA256"
    key => "${LOGSTASH_SALT:-default_salt_please_change}"
    base64encode => true
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    index => "logs-%{+YYYY.MM.dd}"
    user => "logstash_internal"
    password => "${LOGSTASH_PASSWORD}"
    ssl => true
    cacert => "/usr/share/logstash/config/certs/ca/ca.crt"
  }
}
EOF

# Démarrage des containers
echo "🚀 Démarrage du cluster ELK..."
docker-compose up -d elasticsearch

echo "✅ Configuration terminée!"
echo "🔑 Mot de passe Elastic: $ELASTIC_PASSWORD"
echo "🌐 Kibana disponible sur: https://localhost:5601"
