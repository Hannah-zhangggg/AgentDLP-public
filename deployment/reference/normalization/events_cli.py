import argparse
import json
from pathlib import Path

from normalization.core.event_pipeline import UnifiedEventPipeline
from normalization.readers import iter_http_flows


def parse_args():
    parser = argparse.ArgumentParser(description="Normalize Mitmproxy Flow files into unified event v4 JSONL")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--harness-id", default="unknown")
    parser.add_argument("--workload-id")
    parser.add_argument("--session-id")
    return parser.parse_args()


def main():
    args = parse_args()
    run_id = args.run_id or args.input.stem
    pipeline = UnifiedEventPipeline()
    flow_count = 0
    event_count = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.input.open("rb") as source, args.output.open("w", encoding="utf-8") as target:
        for flow in iter_http_flows(
            source,
            run_id,
            args.harness_id,
            workload_id=args.workload_id,
            session_id=args.session_id,
        ):
            flow_count += 1
            for event in pipeline.normalize(flow):
                target.write(json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")
                event_count += 1
    print(f"Flows read: {flow_count}")
    print(f"Events written: {event_count}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
