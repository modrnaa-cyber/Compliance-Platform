import json
import os


def load_cached_findings(target):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    cache_path = os.path.join(project_root, "data", "cache.json")

    if not os.path.exists(cache_path):
        return []

    with open(cache_path, "r", encoding="utf-8") as file:
        cache_data = json.load(file)

    return cache_data.get(target, [])