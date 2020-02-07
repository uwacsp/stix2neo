#!/usr/bin/env python3

import argparse
import json
import sys
from os import listdir
import os
from neo4j import GraphDatabase
from secrets import graph_auth


def attack_to_ckc_index(ckc_name: str) -> int:
    if ckc_name is None:
        return 13
    return ["initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement",
            "collection", "command-and-control", "exfiltration", "impact"].index(ckc_name)


def build_label(txt):
    if txt.startswith('intrusion-set'):
        return 'Group'
    if txt.startswith('malware'):
        return 'Software'
    if txt.startswith('tool'):
        return 'Tool'
    if txt.startswith('attack-pattern'):
        return 'Technique'
    if txt.startswith('identity'):
        return 'Identity'
    raise TypeError(f"Unknown object type: {txt}")


def build_objects(obj):
    kill_chain = obj.get("kill_chain_phases", None)
    if kill_chain is not None:
        phase_name = kill_chain[0].get("phase_name", None)
        phase = attack_to_ckc_index(phase_name)
    else:
        phase = 13

    with driver.session() as session:
        label = build_label(obj['type'])
        session.run(
            f"""
            CREATE (n: {label} {{
                    name: $name,
                    id: $id,
                    created: $created,
                    modified: $modified,
                    description: $description,
                    phase: $phase
                }}
            )
            """,
            name=obj['name'],
            id=obj['id'],
            type=obj['type'],
            created=obj.get('created', "None"),
            modified=obj.get('modified', "None"),
            description=obj.get('description', "None"),
            phase=phase
        )

    # Create relations for aliases
    if obj.get('aliases'):
        aliases = obj['aliases']
    elif obj.get('x_mitre_aliases'):
        aliases = obj['x_mitre_aliases']
    else:
        return  # No Aliases

    for alias in aliases:
        if alias != obj['name']:
            with driver.session() as session:
                session.run(
                    """
                    MATCH (m {id: $id})
                    CREATE (n: Alias { name: $name, type: $type })
                    CREATE (n)-[rel: ALIAS]->(m)
                    """,
                    name=alias, type=obj['type'], id=obj['id']
                )
    return


def build_relations(obj):
    source: str = obj['source_ref']
    target: str = obj['target_ref']

    relation = obj['relationship_type']
    if source.startswith('course-of-action') \
            or target.startswith('course-of-action')\
            or relation.startswith('revoked'):
        return

    with driver.session() as session:
        session.run(
            "MATCH (source {id: $name1}) "
            "MATCH (target {id: $name2}) "
            f"CREATE (source)-[rel: m{relation}]->(target)",
            name1=source,
            name2=target
        )

    print('Relation: "%s" -[%s]-> "%s"' % (source, obj['relationship_type'], target))


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
        files.remove('marking-definition')
        files.remove('enterprise-attack.json')
        files.remove('x-mitre-tactic')
        # Shuffle relationship to the end
        files.remove('relationship')
        files.append('relationship')

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
    # set command-line arguments and parsing options
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', help='input directory', metavar='<dirname>', action='store', required=True)
    args = parser.parse_args()

    # open graph connection
    uri = "bolt://127.0.0.1:7687"

    driver = GraphDatabase.driver(uri, auth=graph_auth, encrypted=False)

    # Delete existing nodes and edges
    with driver.session() as session:
        session.run(
            """
            MATCH (n)
            DETACH DELETE n
            """
        )

    # checks arguments and options
    path = args.i
    assert path is not None, "Path is None"
    recurse_dirs(path, strip=True)
