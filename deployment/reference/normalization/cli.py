import argparse
import json
from pathlib import Path

from normalization.core.pipeline import NormalizationPipeline
from normalization.readers import iter_http_requests


def parse_args():
    parser = argparse.ArgumentParser(description="Normalize Mitmproxy Flow files into AEU JSONL")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--harness-id", default="opencode")
    return parser.parse_args()


def main():
    args = parse_args()
    run_id = args.run_id or args.input.stem
    pipeline = NormalizationPipeline()
    flow_count = 0
    aeu_count = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.input.open("rb") as source, args.output.open("w", encoding="utf-8") as target:
        for request in iter_http_requests(source, run_id, args.harness_id):
            flow_count += 1
            for unit in pipeline.normalize(request):
                target.write(json.dumps(unit.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")
                aeu_count += 1

    print(f"Flows read: {flow_count}")
    print(f"AEUs written: {aeu_count}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
