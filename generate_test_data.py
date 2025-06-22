import logging
import random
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import gzip
import json
from faker import Faker

fake = Faker()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('data/application.log'),
        logging.StreamHandler()
    ]
)

def generate_log_entries(num_entries):
    """Génère des entrées de log réalistes"""
    levels = ['INFO', 'WARNING', 'ERROR', 'DEBUG']
    services = ['auth-service', 'payment-service', 'user-service', 'inventory-service']
    
    for i in range(num_entries):
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
        level = random.choices(levels, weights=[60, 20, 15, 5])[0]
        service = random.choice(services)
        
        if level == 'INFO':
            message = f"Request processed successfully | user_id={fake.uuid4()} | duration={random.randint(50, 500)}ms"
        elif level == 'ERROR':
            message = f"Failed to process request | error={fake.sentence()} | trace_id={fake.uuid4()}"
        else:
            message = fake.sentence()
        
        log_entry = {
            "@timestamp": timestamp.isoformat() + "Z",
            "level": level,
            "service": service,
            "message": message,
            "user_ip": fake.ipv4() if random.random() > 0.7 else None
        }
        
        with open('data/logs/application.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        # Écriture aussi dans un fichier de log standard
        logging.getLogger().log(
            getattr(logging, level),
            f"{service} - {message}"
        )

def generate_xml_events(num_events):
    """Génère des événements XML réalistes"""
    event_types = ['user_login', 'payment_processed', 'inventory_update', 'api_call']
    root = ET.Element('events')
    
    for i in range(num_events):
        event = ET.SubElement(root, 'event')
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
        
        ET.SubElement(event, 'timestamp').text = timestamp.isoformat() + "Z"
        ET.SubElement(event, 'type').text = random.choice(event_types)
        ET.SubElement(event, 'service').text = fake.domain_word() + "-service"
        
        if event.find('type').text == 'user_login':
            ET.SubElement(event, 'user_id').text = fake.uuid4()
            ET.SubElement(event, 'ip_address').text = fake.ipv4()
        elif event.find('type').text == 'payment_processed':
            ET.SubElement(event, 'amount').text = str(round(random.uniform(5, 500), 2))
            ET.SubElement(event, 'currency').text = random.choice(['USD', 'EUR', 'GBP'])
    
    tree = ET.ElementTree(root)
    tree.write('data/xml/events.xml', encoding='utf-8', xml_declaration=True)

def generate_apm_data(num_transactions):
    """Génère des données APM réalistes"""
    transactions = []
    for i in range(num_transactions):
        duration = random.randint(50, 2000)
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
        
        transaction = {
            "@timestamp": timestamp.isoformat() + "Z",
            "service": {"name": random.choice(["frontend", "backend", "payment-service"])},
            "transaction": {
                "id": fake.uuid4(),
                "name": f"{random.choice(['GET', 'POST', 'PUT'])} /api/v{random.randint(1,3)}/{fake.uri_path()}",
                "duration": duration,
                "result": "success" if random.random() > 0.1 else "failure",
                "sampled": True
            }
        }
        
        if transaction["transaction"]["result"] == "failure":
            transaction["error"] = {
                "id": fake.uuid4(),
                "message": random.choice([
                    "Timeout exceeded",
                    "Database connection failed",
                    "Invalid request parameters",
                    "Resource not found"
                ])
            }
        
        transactions.append(transaction)
    
    with gzip.open('data/apm/transactions.ndjson.gz', 'wt') as f:
        for t in transactions:
            f.write(json.dumps(t) + '\n')

if __name__ == "__main__":
    import os
    os.makedirs('data/logs', exist_ok=True)
    os.makedirs('data/xml', exist_ok=True)
    os.makedirs('data/apm', exist_ok=True)
    
    # Génération de 500k logs, 300k événements XML et 200k transactions APM
    generate_log_entries(500000)
    generate_xml_events(300000)
    generate_apm_data(200000)
    
    print("✅ Données de test générées avec succès")
