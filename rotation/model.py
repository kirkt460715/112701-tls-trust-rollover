"""读取并校验证书、客户端与网关三份独立来源。"""

from records_view import load_sources

REQUIRED_SOURCES = ("pki", "clients", "gateways")


def _number(row, key, where):
    value = row.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{where} 的 {key} 需要数值")
    return value


def _text(row, key, where):
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} 的 {key} 需要非空文本")
    return value


def _texts(row, key, where):
    value = row.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where} 的 {key} 需要非空数组")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{where} 的 {key} 只能包含非空文本")
    return list(value)


def _pki(row):
    where = f"pki 记录 {row['id']}"
    if "trusted_root" in row:
        if "chain" in row:
            raise ValueError(f"{where} 同时声明了链和撤销")
        return {
            "kind": "chain",
            "id": row["id"],
            "service": _text(row, "service", where),
            "trusted_root": _text(row, "trusted_root", where),
            "expires": _number(row, "expires", where),
        }
    if "chain" in row:
        return {
            "kind": "revocation",
            "id": row["id"],
            "chain": _text(row, "chain", where),
            "effective": _number(row, "effective", where),
            "received": _number(row, "received", where),
            "event_at": _number(row, "effective", where),
            "known_at": _number(row, "received", where),
        }
    raise ValueError(f"{where} 既不是证书链也不是撤销通知")


def _client(row):
    where = f"clients 记录 {row['id']}"
    if "root" in row:
        if "next_root" in row:
            raise ValueError(f"{where} 同时声明了现状和计划")
        return {
            "kind": "confirmed",
            "id": row["id"],
            "group": _text(row, "group", where),
            "roots": _texts(row, "root", where),
            "confirmed_at": _number(row, "confirmed_at", where),
            "entry": _text(row, "entry", where),
            "event_at": _number(row, "confirmed_at", where),
            "known_at": _number(row, "confirmed_at", where),
        }
    if "next_root" in row:
        return {
            "kind": "plan",
            "id": row["id"],
            "group": _text(row, "group", where),
            "next_root": _text(row, "next_root", where),
            "proposed_at": _number(row, "proposed_at", where),
            "entry": row.get("entry"),
            "event_at": _number(row, "proposed_at", where),
            "known_at": _number(row, "proposed_at", where),
        }
    raise ValueError(f"{where} 既没有已确认的根也没有升级计划")


def _gateway(row):
    where = f"gateways 记录 {row['id']}"
    if "chains" in row:
        if "effective" in row:
            raise ValueError(f"{where} 把接单和生效混在一条记录")
        return {
            "kind": "staged",
            "id": row["id"],
            "entry": _text(row, "entry", where),
            "chains": _texts(row, "chains", where),
            "approved_at": _number(row, "approved_at", where),
            "event_at": _number(row, "approved_at", where),
            "known_at": _number(row, "approved_at", where),
        }
    if "observed_at" in row:
        return {
            "kind": "observation",
            "id": row["id"],
            "entry": _text(row, "entry", where),
            "chain": _text(row, "chain", where),
            "observed_at": _number(row, "observed_at", where),
            "received": _number(row, "received", where),
            "outcome": _text(row, "outcome", where),
            "event_at": _number(row, "observed_at", where),
            "known_at": _number(row, "received", where),
        }
    effective = row.get("effective", "missing")
    if "state" in row:
        if effective not in (None, "missing"):
            raise ValueError(f"{where} 标记为受理却给出了生效时间")
        return {
            "kind": "queued",
            "id": row["id"],
            "entry": _text(row, "entry", where),
            "revision": _text(row, "revision", where),
            "state": _text(row, "state", where),
            "effective": None,
            "event_at": None,
            "known_at": None,
        }
    if effective != "missing":
        return {
            "kind": "applied",
            "id": row["id"],
            "entry": _text(row, "entry", where),
            "revision": _text(row, "revision", where),
            "effective": _number(row, "effective", where),
            "event_at": _number(row, "effective", where),
            "known_at": _number(row, "effective", where),
        }
    raise ValueError(f"{where} 无法识别为接单、生效、排队或观察")


def _latest_event(records):
    times = []
    for row in records["clients"]:
        if row["kind"] in ("confirmed", "plan"):
            times.append(row["event_at"])
    for row in records["gateways"]:
        if row["kind"] in ("staged", "applied", "observation"):
            times.append(row["event_at"])
            times.append(row["known_at"])
    for row in records["revocations"].values():
        times.append(row["event_at"])
        times.append(row["known_at"])
    return max(times)


def load_records(directory):
    """读取三份来源，校验引用关系，并给出可审计的默认观察时刻。"""
    sources = load_sources(directory)
    missing = set(REQUIRED_SOURCES) - set(sources)
    if missing:
        raise ValueError(f"缺少来源: {', '.join(sorted(missing))}")

    chains = {}
    revocations = {}
    for row in sources["pki"]:
        item = _pki(row)
        if item["kind"] == "chain":
            if item["id"] in chains:
                raise ValueError("pki 中的链标识重复")
            chains[item["id"]] = item
        else:
            if item["chain"] in revocations:
                raise ValueError(f"链 {item['chain']} 有多条撤销记录，无法判定")
            revocations[item["chain"]] = item

    for chain_id, row in revocations.items():
        if chain_id not in chains:
            raise ValueError(f"撤销记录 {row['id']} 指向未知的链 {chain_id}")
        if row["effective"] > chains[chain_id]["expires"]:
            raise ValueError(f"撤销记录 {row['id']} 的生效时间晚于链自身有效期")

    clients = [_client(row) for row in sources["clients"]]
    gateways = [_gateway(row) for row in sources["gateways"]]

    roots = {chain["trusted_root"] for chain in chains.values()}
    for row in clients:
        named = row["roots"] if row["kind"] == "confirmed" else [row["next_root"]]
        unknown = set(named) - roots
        if unknown:
            raise ValueError(f"clients 记录 {row['id']} 引用了未知的根 {sorted(unknown)}")

    for row in gateways:
        if row["kind"] in ("staged", "observation"):
            named = row["chains"] if row["kind"] == "staged" else [row["chain"]]
            unknown = set(named) - set(chains)
            if unknown:
                raise ValueError(f"gateways 记录 {row['id']} 引用了未知的链 {sorted(unknown)}")

    records = {
        "chains": chains,
        "revocations": revocations,
        "clients": clients,
        "gateways": gateways,
    }
    records["as_of"] = _latest_event(records)
    return records
