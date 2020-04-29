import pg8000
import json
import sys
import os
import asyncio
from os import listdir
from db_secrets import postgres_addr, postgres_auth, root_directory

table_link = {"intrusion-set": "apt", "malware": "software", "tool": "software", "attack-pattern": "technique"}

tactic_link = {
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    None: None
}


def build_objects(obj):
    label = table_link[obj['type']]
    mitre_id = obj["external_references"][0]["external_id"]

    if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
        return

    cursor = connection.cursor()
    cursor.execute(
        f"""
        INSERT INTO {label} (mitre_id, "name", description, stix_id) 
        VALUES (%s, %s, %s, %s);
        """, (mitre_id, obj["name"], obj.get("description", ""), obj["id"])
    )

    if label == "technique" and obj.get("x_mitre_is_subtechnique", False):
        cursor.execute(
            f"""
            UPDATE technique
            SET is_subtechnique = true
            WHERE mitre_id = %s
            """, (mitre_id,)
        )

    # Create relations for aliases
    if obj.get('aliases'):
        aliases = obj['aliases']
    elif obj.get('x_mitre_aliases'):
        aliases = obj['x_mitre_aliases']
    else:
        return  # No Aliases

    add_aliases(obj['name'], aliases, cursor, label, mitre_id)

    if label == "technique":
        phases = []
        kill_chain = obj.get("kill_chain_phases", [])
        for chain in kill_chain:
            phase_id = tactic_link[chain.get("phase_name", None)]
            if phase_id is not None:
                phases.append(phase_id)

        if len(phases) > 0:
            add_phases(phases, cursor, mitre_id)


def add_phases(phases, cursor, mitre_id):
    for phase in phases:
        cursor.execute(
            """
            INSERT INTO technique_belongs_tactic (technique_id, tactic_id) 
            VALUES (%s, %s);
            """, (mitre_id, phase)
        )


def add_aliases(name, aliases, cursor, label, mitre_id):
    for alias in aliases:
        if alias != name:
            print(name, ":", alias)
            cursor.execute(
                """
                INSERT INTO alias ("name") VALUES (%s) RETURNING "id"
                """, (alias,)
            )
            id_ = cursor.fetchone()[0]
            cursor.execute(
                f"""
                INSERT INTO {label}_alias ({label}_id, alias_id)
                VALUES (%s, %s)
                """, (mitre_id, id_)
            )


def build_relations(obj):
    source: str = obj['source_ref']
    target: str = obj['target_ref']

    relation = obj['relationship_type']
    if source.startswith('course-of-action') \
            or target.startswith('course-of-action') \
            or relation.startswith('revoked'):
        return

    label_links = {"intr": "apt", "malw": "software", "tool": "software", "atta": "technique"}

    label = label_links[source[:4]]
    uses = label_links[target[:4]]

    if label == uses:
        return

    print(source, ":", target)

    cursor = connection.cursor()
    cursor.execute(
        f"""
        INSERT INTO {label}_uses_{uses} 
        SELECT x.mitre_id, y.mitre_id
        FROM (SELECT mitre_id FROM {label} WHERE stix_id = %s) as x,
             (SELECT mitre_id FROM {uses} WHERE stix_id = %s) as y
        """, (source, target)
    )


def process_file(data: dict):
    for obj in data['objects']:
        if obj['type'] == 'relationship':
            build_relations(obj)
        else:
            build_objects(obj)


def recurse_dirs(path: str, strip=False):
    files = listdir(path)
    if strip:
        files.remove('x-mitre-matrix')
        files.remove('README.md')
        files.remove('course-of-action')
        files.remove('identity')
        files.remove('marking-definition')
        files.remove('enterprise-attack.json')
        files.remove('x-mitre-tactic')
        # Shuffle relationship to the end
        files.remove('relationship')
        files.append('relationship')
        files.remove('intrusion-set')
        files.insert(0, 'intrusion-set')
        # files.remove('malware')
        # files.remove('tool')

    for file in files:
        file_path = f'{path}/{file}'
        if os.path.isdir(file_path):
            recurse_dirs(file_path)
        else:
            try:
                with open(file_path, 'r', encoding='utf-8') as fp:
                    data = json.load(fp)
                    process_file(data)
            except json.decoder.JSONDecodeError:
                print(f"FAILED: {file_path}", file=sys.stderr)
            except Exception as e:
                print("Problem.", e, file=sys.stderr)


if __name__ == "__main__":
    connection = pg8000.connect(
        "postgres",
        host=postgres_addr,
        password=postgres_auth
    )

    assert connection is not None, "DB Failed"
    connection.autocommit = True
    path = root_directory + "/VICTIM/cti/enterprise-attack"
    recurse_dirs(path, strip=True)
