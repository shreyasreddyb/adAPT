#!/usr/bin/env python3
"""
Convert Elastic Security Detection Rules (NDJSON) to Sigma Format
"""
import json
import yaml
from pathlib import Path
from datetime import datetime


def parse_ndjson_file(filepath):
    """Parse NDJSON file and return list of rules"""
    rules = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Only process rule objects (skip metadata lines)
                if 'rule_id' in obj and 'name' in obj:
                    rules.append(obj)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON line: {e}")
    return rules


def map_severity(elastic_severity):
    """Map Elastic severity to Sigma level"""
    mapping = {
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical'
    }
    return mapping.get(elastic_severity, 'medium')


def extract_mitre_tags(threat_list):
    """Extract MITRE ATT&CK tags from threat field"""
    tags = []
    for threat in threat_list:
        if threat.get('framework') == 'MITRE ATT&CK':
            tactic = threat.get('tactic', {})
            if tactic.get('name'):
                tags.append(f"attack.{tactic['id'].lower()}")
                tags.append(f"attack.{tactic['name'].lower().replace(' ', '_')}")
            
            for technique in threat.get('technique', []):
                if technique.get('id'):
                    tags.append(f"attack.{technique['id'].lower()}")
    return tags


def convert_kuery_to_sigma(query, rule_type):
    """Convert Kuery query to Sigma detection format"""
    # This is a simplified conversion - may need enhancement
    # Sigma uses different field naming conventions
    
    detection = {
        'selection': {}
    }
    
    # For simple query rules, try to parse basic patterns
    if rule_type == 'query':
        # Simple keyword-based conversion
        detection['selection']['keywords'] = [query]
    elif rule_type == 'eql':
        detection['selection']['eql_query'] = query
    elif rule_type == 'threshold':
        detection['selection']['threshold_query'] = query
    elif rule_type == 'threat_match':
        detection['selection']['threat_match_query'] = query
    
    detection['condition'] = 'selection'
    
    return detection


def convert_elastic_to_sigma(elastic_rule):
    """Convert single Elastic rule to Sigma format"""
    
    # Extract basic metadata
    sigma_rule = {
        'title': elastic_rule.get('name', 'Untitled Rule'),
        'id': elastic_rule.get('rule_id', ''),
        'status': 'stable' if elastic_rule.get('enabled', False) else 'test',
        'description': elastic_rule.get('description', ''),
        'author': elastic_rule.get('author', ['Unknown']),
        'date': datetime.now().strftime('%Y-%m-%d'),
        'modified': elastic_rule.get('updated_at', datetime.now().isoformat()).split('T')[0],
        'references': elastic_rule.get('references', []),
        'tags': []
    }
    
    # Add tags
    tags = []
    if elastic_rule.get('tags'):
        tags.extend(elastic_rule['tags'])
    
    # Add MITRE ATT&CK tags
    if elastic_rule.get('threat'):
        tags.extend(extract_mitre_tags(elastic_rule['threat']))
    
    sigma_rule['tags'] = list(set(tags))  # Remove duplicates
    
    # Map severity
    sigma_rule['level'] = map_severity(elastic_rule.get('severity', 'medium'))
    
    # Convert detection logic
    rule_type = elastic_rule.get('type', 'query')
    query = elastic_rule.get('query', '')
    
    sigma_rule['logsource'] = {
        'category': 'process_creation' if 'process' in query.lower() else 'unknown',
        'product': 'windows' if 'windows' in str(elastic_rule.get('tags', [])).lower() else 'linux'
    }
    
    # Add indices as custom fields
    if elastic_rule.get('index'):
        sigma_rule['logsource']['index'] = elastic_rule['index']
    
    # Convert query to detection
    sigma_rule['detection'] = convert_kuery_to_sigma(query, rule_type)
    
    # Add false positives
    if elastic_rule.get('false_positives'):
        sigma_rule['falsepositives'] = elastic_rule['false_positives']
    else:
        sigma_rule['falsepositives'] = ['Unknown']
    
    # Add fields
    fields = []
    if elastic_rule.get('required_fields'):
        fields = [field.get('name') for field in elastic_rule['required_fields']]
    sigma_rule['fields'] = fields
    
    return sigma_rule


def sanitize_filename(name):
    """Create safe filename from rule name"""
    # Remove invalid characters and spaces
    safe_name = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in name)
    safe_name = safe_name.replace(' ', '_').lower()
    # Limit length
    return safe_name[:100]


def main():
    """Main conversion function"""
    # Input files
    input_files = [
        'rules_export (12).ndjson',
        'rules_export (13).ndjson'
    ]
    
    # Output directory
    output_dir = Path('sigma_rules')
    output_dir.mkdir(exist_ok=True)
    
    total_rules = 0
    converted_rules = 0
    
    for input_file in input_files:
        print(f"\nProcessing {input_file}...")
        
        if not Path(input_file).exists():
            print(f"  Warning: File not found, skipping")
            continue
        
        # Parse rules
        rules = parse_ndjson_file(input_file)
        print(f"  Found {len(rules)} rules")
        total_rules += len(rules)
        
        # Convert each rule
        for rule in rules:
            try:
                sigma_rule = convert_elastic_to_sigma(rule)
                
                # Generate filename
                filename = sanitize_filename(rule.get('name', 'unknown'))
                output_file = output_dir / f"{filename}.yml"
                
                # Handle duplicate filenames
                counter = 1
                while output_file.exists():
                    output_file = output_dir / f"{filename}_{counter}.yml"
                    counter += 1
                
                # Write Sigma rule to YAML
                with open(output_file, 'w', encoding='utf-8') as f:
                    # Add custom YAML formatting
                    yaml.dump(sigma_rule, f, default_flow_style=False, 
                             allow_unicode=True, sort_keys=False, indent=2)
                
                converted_rules += 1
                
            except Exception as e:
                print(f"  Error converting rule '{rule.get('name', 'unknown')}': {e}")
    
    print(f"\n{'='*60}")
    print(f"Conversion Summary:")
    print(f"  Total rules found: {total_rules}")
    print(f"  Successfully converted: {converted_rules}")
    print(f"  Failed: {total_rules - converted_rules}")
    print(f"  Output directory: {output_dir.absolute()}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
