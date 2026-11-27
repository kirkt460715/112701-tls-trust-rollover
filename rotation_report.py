"""按站点和入口办理 TLS 信任轮换的审核，离线读取本地合成记录。

默认输出全部服务的核对结论。可用 --service / --entry / --client 收窄，
--as-of 指定判断时点，--json 输出完整结构。
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rotation import evaluate, load_records  # noqa: E402
from rotation.evaluate import summarize_entries  # noqa: E402


def _focus(report, service, entry, client):
    """保留完整结构，只筛选服务、入口或站点，便于按需核对。"""
    selected = []
    for item in report["services"]:
        if service and item["service"] != service:
            continue
        item = json.loads(json.dumps(item))
        if entry:
            item["entries"] = [e for e in item["entries"] if e["entry"] == entry]
        if client:
            for e in item["entries"]:
                e["stations"] = {cid: s for cid, s in e["stations"].items()
                                 if cid == client}
            item["entries"] = [e for e in item["entries"] if e["stations"]]
        if entry or client:
            item.update(summarize_entries(item["entries"]))
        if not item["entries"]:
            continue
        selected.append(item)
    report["services"] = selected
    return report


def _brief(report):
    lines = [f"核对时点 {report['as_of']}"]
    for service in report["services"]:
        lines.append(f"服务 {service['service']}: {service['status']}")
        for entry in service["entries"]:
            line = f"  入口 {entry['entry']}: {entry['status']}"
            if entry["both_sides_from"] is not None:
                line += f"，两侧就绪于 {entry['both_sides_from']}"
            if entry["missing_evidence"]:
                line += f"，仍缺 {', '.join(entry['missing_evidence'])}"
            if entry["owner"]:
                line += f"（负责方：{entry['owner']}）"
            lines.append(line)
            for cid, station in entry["stations"].items():
                detail = f"    站点 {cid}: {station['state']}"
                if station.get("ready_from") is not None:
                    detail += f"，新链就绪于 {station['ready_from']}"
                if station.get("usable_old_until") is not None:
                    detail += f"，旧链可用至 {station['usable_old_until']}"
                if station["reason"]:
                    detail += f"（{station['reason']}）"
                lines.append(detail)
            for plan in entry["plans"]:
                lines.append(f"    计划 {plan['id']}: 拟换到 {plan['next_root']}"
                             f"（{plan['proposed_at']} 提出，未生效）")
            for obs in entry["old_chain"]["observations"]:
                if obs["conflict"]:
                    lines.append(f"    回执 {obs['id']}: {obs['note']}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--records", type=Path, default=Path(__file__).with_name("records"))
    parser.add_argument("--service")
    parser.add_argument("--entry")
    parser.add_argument("--client")
    parser.add_argument("--as-of", type=int, dest="as_of")
    parser.add_argument("--json", action="store_true", help="输出完整 JSON")
    args = parser.parse_args()
    try:
        records = load_records(args.records)
        report = evaluate(records, args.as_of)
        report = _focus(report, args.service, args.entry, args.client)
        if not report["services"]:
            if args.service:
                raise ValueError("服务不存在")
            raise ValueError("给定的筛选条件没有匹配记录")
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else _brief(report))


if __name__ == "__main__":
    main()
