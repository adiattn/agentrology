#!/usr/bin/env python3
import json
import os

current_path = os.path.dirname(os.path.abspath(__file__))

if current_path.endswith("scripts"):
    benchmark_path = os.path.join(os.path.dirname(current_path), "benchmarks")
else:
    benchmark_path = os.path.join(current_path, "benchmarks")

count = 0
total = 0
for filename in os.listdir(benchmark_path):
    if filename.endswith(".json"):
        file_path = os.path.join(benchmark_path, filename)
        if not os.path.isfile(file_path):
            continue
        with open(file_path, "r") as f:
            data = json.load(f)

        if data["summary"]["neutralized_threats"] <= 0:
            os.remove(file_path)
            count += 1
            print(f"- Removed {filename}")
        total += 1

print(f"Cleaned {count} files out of {total} total files.")
