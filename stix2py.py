#!/usr/bin/env python3

import argparse
import json
import sys
from os import listdir
import os

groups = {}
ids_to_name = {}
ids_to_tech = {}


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
    kill_chain = obj.get("kill_chain_phases", [])
    phase = 13
    for chain in kill_chain:
        phase_name = chain.get("phase_name", None)
        phase = p if (p := attack_to_ckc_index(phase_name)) < phase else phase

    label = build_label(obj['type'])
    if label == 'Group':
        print(obj['id'])
        groups[obj['name']] = set()
        ids_to_name[obj['id']] = obj['name']

    if label == 'Technique':
        print(obj['id'])
        ids_to_tech[obj['id']] = obj['name']
    return


def build_relations(obj):
    source: str = obj['source_ref']
    target: str = obj['target_ref']

    if source.startswith('intrusion-set') \
            and target.startswith('attack-pattern'):
        source = ids_to_name[source]
        target = ids_to_tech[target]
        groups[source].add(target)


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
    path = '/Users/lachierussell/Developer/research/VICTIM/MitreStix/enterprise-attack/'
    assert path is not None, "Path is None"
    recurse_dirs(path, strip=True)
    print(groups)

    with open('group-techs.csv', 'w') as fp:
        for group in groups.items():
            fp.write(f'{group[0]},')
            techniques = sorted(group[1])
            for technique in techniques:
                fp.write(f'{technique},')
            fp.write('\n')
