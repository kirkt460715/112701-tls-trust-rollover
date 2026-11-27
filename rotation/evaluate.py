"""按站点和入口核对轮换证据，给出可续办的结论与缺口。

设计取舍：
- 网关“接单/受理”和“实际生效”分开核对，生效必须晚于批准。
- 计划升级只作记录，不算客户端已信任新链。
- 同一服务的每个入口独立核对，不能拿一处观察替另一处签认。
- 撤销通知到达后，旧链不再作为回退；维护单批准也不能推翻这一点。
- 所有时点都取自原始记录字段，判断按调用方给定或记录中最晚的已知时刻。
"""

# 服务层结论。
PROCEED = "proceed"        # 全部入口新旧两侧信任都已满足
PARTIAL = "partial"        # 部分入口可先往前办，其余仍有缺口
BLOCKED = "blocked"        # 没有入口可签认
OVERLAP = "overlap_active"  # 仍在重叠期

# 入口/站点层结论。
STABLE_NEW = "stable_new"  # 已可稳定使用新链
OVERLAP_ACTIVE = "overlap_active"  # 旧链仍可依赖到停用时点
AT_RISK = "at_risk"        # 旧链已停而新链未就绪，可能中断
BLOCKED_ENTRY = "blocked"  # 缺批准或证据冲突
UNKNOWN = "unknown"        # 证据不足


def _sorted(rows, key):
    return sorted(rows, key=lambda row: (row[key], row["id"]))


def _chain_stop(records, chain, as_of):
    """旧链可信的终点：自身有效期与撤销生效取早者。

    撤销通知到达后即不可回退，即使维护单批准过重叠期。
    """
    stop = chain["expires"]
    source = "expiry"
    revocation = records["revocations"].get(chain["id"])
    if revocation and revocation["effective"] < stop:
        stop = revocation["effective"]
        source = "revocation"
    received = revocation["received"] if revocation else None
    revoked_now = received is not None and as_of >= received
    # 依赖旧链的截止时点：技术有效期/撤销生效取早，撤销通知到达再取早。
    reliance_stop = min(stop, received) if received is not None else stop
    return {
        "stop": stop,
        "stop_source": source,
        "revoked_at": revocation["effective"] if revocation else None,
        "notice_received": received,
        "revocation_record": revocation["id"] if revocation else None,
        "reliance_stop": reliance_stop,
        # 撤销生效或通知到达，先到者即关闭回退；维护单批准不能推翻。
        "fallback_allowed": as_of < reliance_stop,
        "revocation_overrides_approval": revoked_now,
    }


def _gateway_state(records, entry, chain_id, as_of):
    """分别核对网关接单、实际生效与入口上对该链的后续观察。"""
    approvals = [row for row in records["gateways"]
                 if row["kind"] == "staged" and row["entry"] == entry
                 and chain_id in row["chains"] and row["approved_at"] <= as_of]
    applied = [row for row in records["gateways"]
               if row["kind"] == "applied" and row["entry"] == entry
               and row["effective"] <= as_of]
    queued = [row for row in records["gateways"]
              if row["kind"] == "queued" and row["entry"] == entry]
    observations = _sorted(
        [row for row in records["gateways"]
         if row["kind"] == "observation" and row["entry"] == entry
         and row["chain"] == chain_id and row["received"] <= as_of],
        "observed_at")

    base = {
        "observations": observations,
        "accepted_but_not_effective": sorted(row["id"] for row in queued),
        "approval_basis": [{"id": row["id"], "approved_at": row["approved_at"],
                            "chains": row["chains"]} for row in approvals],
    }
    if not approvals:
        return {**base, "approved": False, "applied": False,
                "live_from": None, "gap": "not_approved"}
    approved_at = max(row["approved_at"] for row in approvals)
    # 接单不算生效；生效还必须晚于批准，否则这次变更并未覆盖该链。
    effective = sorted(row["effective"] for row in applied
                       if row["effective"] >= approved_at)
    if not effective:
        return {**base, "approved": True, "applied": False,
                "live_from": None, "gap": "accepted_not_effective"}
    return {**base, "approved": True, "applied": True,
            "live_from": effective[0], "gap": None}


def _latest_confirmed(records, entry, as_of):
    latest = {}
    for row in _sorted([r for r in records["clients"]
                        if r["kind"] == "confirmed" and r["entry"] == entry
                        and r["confirmed_at"] <= as_of], "confirmed_at"):
        latest[row["id"]] = row
    return latest


def _plans_for(records, entry, group, as_of):
    """升级计划记录在案，但不算已经生效。"""
    result = []
    for row in records["clients"]:
        if row["kind"] != "plan" or row["proposed_at"] > as_of:
            continue
        if row["entry"] == entry or (row["entry"] is None and row["group"] == group):
            result.append(row)
    return result


def _client_ready(clients, chain):
    missing = sorted(cid for cid, row in clients.items()
                     if chain["trusted_root"] not in row["roots"])
    if not clients:
        return None, "no_confirmed_client", missing
    if missing:
        return None, "client_not_trusting", missing
    return max(row["confirmed_at"] for row in clients.values()), None, []


def _observation_conflicts(observations, stop):
    """回执与撤销/过期冲突：捕获时可信，但到回执时已不能作为签认依据。"""
    result = []
    for row in observations:
        stale = row["observed_at"] < stop <= row["received"]
        result.append({
            "id": row["id"],
            "observed_at": row["observed_at"],
            "received": row["received"],
            "outcome_at_capture": row["outcome"],
            "valid_at_capture": row["observed_at"] < stop,
            "usable_at_receipt": row["received"] < stop,
            "conflict": stale,
            "note": ("捕获时该链尚未停用，但回执晚于停用时点到达，"
                     "不能据此继续签认" if stale else None),
        })
    return result


def _entry_report(records, entry, chains, as_of):
    old, new = chains[0], chains[-1]
    clients = _latest_confirmed(records, entry, as_of)
    groups = {row["group"] for row in clients.values()}
    plans = [plan for group in sorted(groups)
             for plan in _plans_for(records, entry, group, as_of)]

    new_gateway = _gateway_state(records, entry, new["id"], as_of)
    old_gateway = _gateway_state(records, entry, old["id"], as_of)
    new_client_from, new_client_gap, new_missing = _client_ready(clients, new)
    old_stop = _chain_stop(records, old, as_of)
    new_stop = _chain_stop(records, new, as_of)

    both_from = None
    if new_gateway["live_from"] is not None and new_client_from is not None:
        both_from = max(new_gateway["live_from"], new_client_from)
    ready = both_from is not None and both_from <= as_of
    # 站点是否已断，看链本身何时失去信任（stop），不看通知何时到达。
    old_expired = old_stop["stop"] <= as_of

    stations = {}
    for cid, row in sorted(clients.items()):
        trusts_new = new["trusted_root"] in row["roots"]
        trusts_old = old["trusted_root"] in row["roots"]
        ready_from = None
        if trusts_new and new_gateway["live_from"] is not None:
            ready_from = max(new_gateway["live_from"], row["confirmed_at"])
            state, reason = STABLE_NEW, None
        elif trusts_old and old_expired:
            state, reason = AT_RISK, "旧链已停用且新链未在该入口生效"
        elif trusts_old:
            state, reason = OVERLAP_ACTIVE, None
        else:
            state, reason = BLOCKED_ENTRY, "既未信任旧链也未信任新链"
        stations[cid] = {
            "group": row["group"],
            "roots": row["roots"],
            "confirmed_at": row["confirmed_at"],
            "trusts_old": trusts_old,
            "trusts_new": trusts_new,
            "state": state,
            "reason": reason,
            "ready_from": ready_from,
            "usable_old_until": old_stop["reliance_stop"] if trusts_old else None,
        }

    # 入口结论：先看新链两侧是否都就绪，再区分缺批准、缺信任和时点问题。
    if not clients:
        status, missing, owner = UNKNOWN, ["confirmed_client"], "客户端维护人"
    elif new_gateway["gap"] == "not_approved":
        status, missing, owner = BLOCKED_ENTRY, ["gateway_not_approved"], "变更审批人"
        if new_missing:
            missing.append("client_not_trusting")
        if old_expired:
            missing.append("old_chain_already_stopped")
    elif new_missing:
        status, missing, owner = BLOCKED_ENTRY, ["client_not_trusting"], "客户端维护人"
        if old_expired:
            missing.append("old_chain_already_stopped")
    elif ready:
        status, missing, owner = STABLE_NEW, [], None
    elif old_expired:
        status, missing, owner = AT_RISK, ["new_chain_not_effective"], "网关值班台"
    else:
        status, missing, owner = OVERLAP_ACTIVE, ["new_chain_not_effective"], "网关值班台"
        if new_gateway["gap"] == "accepted_not_effective":
            missing.append("gateway_accepted_not_effective")

    old_client_trust = [row["confirmed_at"] for row in clients.values()
                        if old["trusted_root"] in row["roots"]]
    old_usable_from = None
    if old_gateway["live_from"] is not None and old_client_trust:
        old_usable_from = max(old_gateway["live_from"], max(old_client_trust))

    # 批准重叠期时要能核对三件事：旧链可用到哪、新链哪天才两侧就绪、
    # 何时必须停止依赖旧链。两侧没有交集时 exists 为假。
    overlap = {
        "exists": both_from is not None and both_from < old_stop["reliance_stop"],
        "old_usable_from": old_usable_from,
        "old_usable_until": old_stop["reliance_stop"],
        "new_ready_from": both_from,
        "must_stop_relying_at": old_stop["reliance_stop"],
        "basis": old_stop["stop_source"],
    }

    return {
        "entry": entry,
        "status": status,
        "ready": ready,
        "both_sides_from": both_from,
        "missing_evidence": missing,
        "owner": owner,
        "overlap": overlap,
        "old_chain": {
            "chain": old["id"],
            "root": old["trusted_root"],
            **old_stop,
            "gateway_approved": old_gateway["approved"],
            "gateway_live_from": old_gateway["live_from"],
            "observations": _observation_conflicts(
                old_gateway["observations"], old_stop["stop"]),
        },
        "new_chain": {
            "chain": new["id"],
            "root": new["trusted_root"],
            "gateway_approved": new_gateway["approved"],
            "gateway_live_from": new_gateway["live_from"],
            "gateway_gap": new_gateway["gap"],
            "accepted_but_not_effective": new_gateway["accepted_but_not_effective"],
            "client_trust_from": new_client_from,
            "client_gap": new_client_gap,
            "clients_missing_trust": new_missing,
            "both_sides_from": both_from,
            "stop": new_stop["stop"],
            "observations": _observation_conflicts(
                new_gateway["observations"], new_stop["stop"]),
        },
        "other_chains": [chain["id"] for chain in chains[1:-1]],
        "stations": stations,
        "plans": [{"id": plan["id"], "group": plan["group"],
                   "next_root": plan["next_root"],
                   "proposed_at": plan["proposed_at"],
                   "effective": False} for plan in sorted(plans, key=lambda r: r["id"])],
        "approval_basis": {
            "gateway": new_gateway["approval_basis"],
            "client_confirmations": [
                {"id": cid, "confirmed_at": row["confirmed_at"], "roots": row["roots"]}
                for cid, row in sorted(clients.items())
            ],
            "revocation": ({"id": old_stop["revocation_record"],
                            "effective": old_stop["revoked_at"],
                            "received": old_stop["notice_received"]}
                           if old_stop["revocation_record"] else None),
        },
    }


def _service_chains(records):
    services = {}
    for chain in records["chains"].values():
        services.setdefault(chain["service"], []).append(chain)
    for chains in services.values():
        chains.sort(key=lambda row: (row["expires"], row["id"]))
    return services


def _entries_for(records, chains):
    roots = {chain["trusted_root"] for chain in chains}
    chain_ids = {chain["id"] for chain in chains}
    approved_entries = {row["entry"] for row in records["gateways"]
                        if row["kind"] == "staged" and set(row["chains"]) & chain_ids}
    entries = set()
    group_entry = {}
    for row in records["clients"]:
        if row["kind"] == "confirmed" and set(row["roots"]) & roots:
            entries.add(row["entry"])
            group_entry.setdefault(row["group"], row["entry"])
    entries |= approved_entries
    for row in records["gateways"]:
        if row["kind"] in ("applied", "queued") and row["entry"] in approved_entries:
            entries.add(row["entry"])
    for row in records["clients"]:
        if row["kind"] == "plan":
            entry = row["entry"] or group_entry.get(row["group"])
            if entry:
                entries.add(entry)
    return sorted(entries)


def summarize_entries(entries):
    """按入口结论汇总服务状态；筛选入口后也可复用同一规则。"""
    stable = [e["entry"] for e in entries if e["status"] == STABLE_NEW]
    blocked = [e["entry"] for e in entries if e["status"] == BLOCKED_ENTRY]
    at_risk = sorted({(item["entry"], cid)
                      for item in entries
                      for cid, station in item["stations"].items()
                      if station["state"] == AT_RISK})
    if not entries:
        overall = UNKNOWN
    elif len(stable) == len(entries):
        overall = PROCEED
    elif stable:
        overall = PARTIAL
    elif at_risk:
        overall = AT_RISK
    elif blocked:
        overall = BLOCKED_ENTRY
    else:
        overall = OVERLAP
    return {
        "status": overall,
        "stable_entries": stable,
        "blocked_entries": blocked,
        "at_risk_stations": [{"entry": entry, "client": cid}
                             for entry, cid in at_risk],
    }


def evaluate(records, as_of=None):
    """按服务、入口、站点三层给出轮换结论；默认用记录中最晚的已知时刻。"""
    as_of = records["as_of"] if as_of is None else as_of
    services = _service_chains(records)
    if not services:
        raise ValueError("没有可核对的证书链")

    report = {"as_of": as_of, "services": []}
    for service, chains in sorted(services.items()):
        if len(chains) < 2:
            report["services"].append({
                "service": service,
                "status": UNKNOWN,
                "missing_evidence": ["replacement_chain"],
                "entries": [],
            })
            continue
        entries = [_entry_report(records, entry, chains, as_of)
                   for entry in _entries_for(records, chains)]
        report["services"].append({
            "service": service,
            **summarize_entries(entries),
            "entries": entries,
        })
    return report
