"""Compact per-function data-flow summaries from Ghidra High P-code.

This module intentionally has no imports from ``ghidra.*``.  The objects it
receives are Java objects exposed by JPype after PyGhidra starts the JVM, but
keeping the implementation duck-typed preserves the package's lazy-import
contract and makes the extraction logic unit-testable without Ghidra.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

DATA_FLOW_SCHEMA_VERSION = 1
MAX_TRACE_DEPTH = 128

COMPARISON_OPERATORS = {
    "INT_EQUAL": "==",
    "INT_NOTEQUAL": "!=",
    "INT_LESS": "<u",
    "INT_LESSEQUAL": "<=u",
    "INT_SLESS": "<s",
    "INT_SLESSEQUAL": "<=s",
    "FLOAT_EQUAL": "==",
    "FLOAT_NOTEQUAL": "!=",
    "FLOAT_LESS": "<",
    "FLOAT_LESSEQUAL": "<=",
    "FLOAT_NAN": "isnan",
}

CALL_OPS = {"CALL", "CALLIND"}
SOURCE_KINDS = {"parameter", "call_result"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _deduplicate(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical(value): value for value in values}
    return [unique[key] for key in sorted(unique)]


def _safe_call(obj: Any, method: str, default: Any = None) -> Any:
    try:
        return getattr(obj, method)()
    except Exception:
        return default


def _safe_size(varnode: Any) -> int | None:
    value = _safe_call(varnode, "getSize")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _op_location(op: Any) -> tuple[str, int]:
    seqnum = _safe_call(op, "getSeqnum")
    if seqnum is None:
        return "unknown", -1
    address = _safe_call(seqnum, "getTarget", "unknown")
    index = _safe_call(seqnum, "getTime", -1)
    try:
        pcode_index = int(index)
    except (TypeError, ValueError):
        pcode_index = -1
    return str(address), pcode_index


def _op_id(prefix: str, op: Any) -> str:
    address, pcode_index = _op_location(op)
    return f"{prefix}:{address}:{pcode_index}"


def _opcode(op: Any) -> str:
    value = _safe_call(op, "getMnemonic", "UNKNOWN")
    return str(value).upper()


def _inputs(op: Any) -> list[Any]:
    count = _safe_call(op, "getNumInputs", 0)
    try:
        return [op.getInput(index) for index in range(int(count))]
    except Exception:
        return []


def _varnode_key(varnode: Any) -> str:
    defining_op = _safe_call(varnode, "getDef")
    if defining_op is not None:
        return f"def:{_op_id('op', defining_op)}"
    address = _safe_call(varnode, "getAddress", "unknown")
    pc_address = _safe_call(varnode, "getPCAddress", "unknown")
    high_variable = _safe_call(varnode, "getHigh")
    high_name = (
        _safe_call(high_variable, "getName", "") if high_variable is not None else ""
    )
    high_slot = (
        _safe_call(high_variable, "getSlot", "") if high_variable is not None else ""
    )
    size = _safe_size(varnode)
    return (
        f"leaf:{address}:{pc_address}:{size}:{high_name}:{high_slot}:"
        f"{bool(_safe_call(varnode, 'isInput', False))}"
    )


def _hex_constant(varnode: Any) -> str:
    raw_value = _safe_call(varnode, "getOffset", 0)
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        value = 0
    size = _safe_size(varnode)
    if size and size > 0:
        value &= (1 << (size * 8)) - 1
    return f"0x{value:x}"


class _OriginTracer:
    def __init__(
        self,
        call_by_op: dict[str, dict[str, Any]],
        *,
        max_depth: int = MAX_TRACE_DEPTH,
    ):
        self.call_by_op = call_by_op
        self.max_depth = max_depth
        self.cache: dict[str, list[dict[str, Any]]] = {}
        self.truncated_traces = 0

    def value(self, varnode: Any) -> dict[str, Any]:
        if varnode is None:
            return {"size": None, "origins": [{"kind": "unknown"}]}
        return {
            "size": _safe_size(varnode),
            "origins": self.trace(varnode),
        }

    def trace(
        self,
        varnode: Any,
        *,
        depth: int = 0,
        active: frozenset[str] = frozenset(),
    ) -> list[dict[str, Any]]:
        if varnode is None:
            return [{"kind": "unknown"}]

        key = _varnode_key(varnode)
        if key in self.cache:
            return self.cache[key]
        if depth >= self.max_depth:
            self.truncated_traces += 1
            return [
                {
                    "kind": "trace_limit",
                    "storage": str(_safe_call(varnode, "getAddress", "unknown")),
                }
            ]
        if key in active:
            return [
                {
                    "kind": "cycle",
                    "storage": str(_safe_call(varnode, "getAddress", "unknown")),
                }
            ]

        if bool(_safe_call(varnode, "isConstant", False)):
            result = [
                {
                    "kind": "constant",
                    "value": _hex_constant(varnode),
                    "size": _safe_size(varnode),
                }
            ]
            self.cache[key] = result
            return result

        parameter = self._parameter_origin(varnode)
        if parameter is not None:
            result = [parameter]
            self.cache[key] = result
            return result

        defining_op = _safe_call(varnode, "getDef")
        if defining_op is None:
            result = [self._leaf_origin(varnode)]
            self.cache[key] = result
            return result

        mnemonic = _opcode(defining_op)
        if mnemonic in CALL_OPS:
            call = self.call_by_op.get(_op_id("op", defining_op))
            result = [
                {
                    "kind": "call_result",
                    "callId": call["id"] if call else _op_id("call", defining_op),
                    "address": _op_location(defining_op)[0],
                    "target": call.get("target") if call else None,
                    "size": _safe_size(varnode),
                }
            ]
            self.cache[key] = result
            return result

        op_inputs = _inputs(defining_op)
        next_active = active | {key}
        if mnemonic == "LOAD":
            pointer = op_inputs[1] if len(op_inputs) > 1 else None
            result = [
                {
                    "kind": "memory_load",
                    "address": _op_location(defining_op)[0],
                    "size": _safe_size(varnode),
                    "pointerOrigins": (
                        self.trace(
                            pointer,
                            depth=depth + 1,
                            active=next_active,
                        )
                        if pointer is not None
                        else [{"kind": "unknown"}]
                    ),
                }
            ]
            self.cache[key] = result
            return result

        if mnemonic == "CALLOTHER":
            result = [
                {
                    "kind": "operation_result",
                    "operation": mnemonic,
                    "address": _op_location(defining_op)[0],
                    "size": _safe_size(varnode),
                }
            ]
            self.cache[key] = result
            return result

        # INDIRECT's second input identifies the causing operation; it is not a
        # data input.  The first input is the value propagated through it.
        if mnemonic == "INDIRECT":
            op_inputs = op_inputs[:1]

        origins: list[dict[str, Any]] = []
        for input_varnode in op_inputs:
            origins.extend(
                self.trace(
                    input_varnode,
                    depth=depth + 1,
                    active=next_active,
                )
            )
        if not origins:
            origins.append(
                {
                    "kind": "operation_result",
                    "operation": mnemonic,
                    "address": _op_location(defining_op)[0],
                    "size": _safe_size(varnode),
                }
            )
        result = _deduplicate(origins)
        self.cache[key] = result
        return result

    def _parameter_origin(self, varnode: Any) -> dict[str, Any] | None:
        high_variable = _safe_call(varnode, "getHigh")
        if high_variable is None:
            return None
        slot = _safe_call(high_variable, "getSlot")
        if slot is None:
            return None
        try:
            index = int(slot)
        except (TypeError, ValueError):
            return None
        data_type = _safe_call(high_variable, "getDataType")
        return {
            "kind": "parameter",
            "id": f"param:{index}",
            "index": index,
            "name": str(_safe_call(high_variable, "getName", f"param_{index}")),
            "type": str(data_type) if data_type is not None else None,
            "size": _safe_size(varnode),
        }

    def _leaf_origin(self, varnode: Any) -> dict[str, Any]:
        high_variable = _safe_call(varnode, "getHigh")
        name = (
            _safe_call(high_variable, "getName") if high_variable is not None else None
        )
        data_type = (
            _safe_call(high_variable, "getDataType")
            if high_variable is not None
            else None
        )
        if bool(_safe_call(varnode, "isInput", False)):
            kind = "function_input"
        elif bool(_safe_call(varnode, "isPersistent", False)):
            kind = "persistent"
        else:
            kind = "unknown"
        return {
            "kind": kind,
            "storage": str(_safe_call(varnode, "getAddress", "unknown")),
            "name": str(name) if name is not None else None,
            "type": str(data_type) if data_type is not None else None,
            "size": _safe_size(varnode),
        }


def _parameter_descriptors(
    high_function: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    unresolved: list[dict[str, Any]] = []
    try:
        symbol_map = high_function.getLocalSymbolMap()
        count = int(symbol_map.getNumParams())
    except Exception as exc:
        return [], [{"kind": "parameters", "reason": str(exc)}]

    parameters: list[dict[str, Any]] = []
    for index in range(count):
        try:
            parameter = symbol_map.getParam(index)
            data_type = _safe_call(parameter, "getDataType")
            representative = _safe_call(parameter, "getRepresentative")
            parameters.append(
                {
                    "id": f"param:{index}",
                    "index": index,
                    "name": str(_safe_call(parameter, "getName", f"param_{index}")),
                    "type": str(data_type) if data_type is not None else None,
                    "size": _safe_size(representative),
                    "storage": str(_safe_call(representative, "getAddress", "unknown")),
                }
            )
        except Exception as exc:
            unresolved.append(
                {
                    "kind": "parameter",
                    "index": index,
                    "reason": str(exc),
                }
            )
    return parameters, unresolved


def _find_comparisons(varnode: Any) -> list[Any]:
    pending = [varnode]
    visited: set[str] = set()
    comparisons: dict[str, Any] = {}
    while pending:
        current = pending.pop()
        if current is None:
            continue
        key = _varnode_key(current)
        if key in visited:
            continue
        visited.add(key)
        defining_op = _safe_call(current, "getDef")
        if defining_op is None:
            continue
        mnemonic = _opcode(defining_op)
        if mnemonic in COMPARISON_OPERATORS:
            comparisons[_op_id("check", defining_op)] = defining_op
            continue
        if mnemonic in CALL_OPS or mnemonic in {"LOAD", "CALLOTHER"}:
            continue
        op_inputs = _inputs(defining_op)
        if mnemonic == "INDIRECT":
            op_inputs = op_inputs[:1]
        pending.extend(op_inputs)
    return [comparisons[key] for key in sorted(comparisons)]


def _source_origins(origins: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [origin for origin in origins if origin.get("kind") in SOURCE_KINDS]


def extract_function_flow(
    high_function: Any,
    *,
    function_name: str,
    function_address: str,
    resolve_direct_call: Callable[[Any], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Extract direct, function-local flow facts from a HighFunction."""

    operations = list(high_function.getPcodeOps())
    parameters, unresolved = _parameter_descriptors(high_function)

    calls: list[dict[str, Any]] = []
    call_by_op: dict[str, dict[str, Any]] = {}
    for op in operations:
        mnemonic = _opcode(op)
        if mnemonic not in CALL_OPS:
            continue
        address, pcode_index = _op_location(op)
        op_inputs = _inputs(op)
        target_varnode = op_inputs[0] if op_inputs else None
        if mnemonic == "CALL":
            target = (
                resolve_direct_call(target_varnode)
                if resolve_direct_call is not None and target_varnode is not None
                else None
            )
            if target is None:
                target = {
                    "kind": "direct",
                    "address": str(_safe_call(target_varnode, "getAddress", "unknown")),
                    "name": None,
                    "external": None,
                }
            else:
                target = {"kind": "direct", **target}
        else:
            target = {"kind": "indirect"}

        output = _safe_call(op, "getOutput")
        call = {
            "id": _op_id("call", op),
            "address": address,
            "pcodeIndex": pcode_index,
            "target": target,
            "arguments": [],
            "result": (
                {
                    "id": f"{_op_id('call', op)}:result",
                    "size": _safe_size(output),
                }
                if output is not None
                else None
            ),
        }
        calls.append(call)
        call_by_op[_op_id("op", op)] = call

    tracer = _OriginTracer(call_by_op)

    for op in operations:
        mnemonic = _opcode(op)
        if mnemonic not in CALL_OPS:
            continue
        call = call_by_op[_op_id("op", op)]
        op_inputs = _inputs(op)
        if mnemonic == "CALLIND" and op_inputs:
            call["target"]["value"] = tracer.value(op_inputs[0])
            unresolved.append(
                {
                    "kind": "indirect_call",
                    "address": call["address"],
                    "callId": call["id"],
                }
            )
        call["arguments"] = [
            {
                "index": index - 1,
                **tracer.value(op_inputs[index]),
            }
            for index in range(1, len(op_inputs))
        ]

    checks: list[dict[str, Any]] = []
    for branch in operations:
        if _opcode(branch) != "CBRANCH":
            continue
        branch_inputs = _inputs(branch)
        if len(branch_inputs) < 2:
            unresolved.append(
                {
                    "kind": "conditional_branch",
                    "address": _op_location(branch)[0],
                    "reason": "missing condition input",
                }
            )
            continue
        condition = branch_inputs[1]
        branch_address, branch_index = _op_location(branch)
        branch_target = {
            "encoding": str(_safe_call(branch_inputs[0], "getAddress", "unknown")),
            # Constant-space branch destinations are offsets in the P-code
            # stream, not machine-code addresses.
            "relativePcode": bool(_safe_call(branch_inputs[0], "isConstant", False)),
        }
        comparisons = _find_comparisons(condition)

        if comparisons:
            for comparison in comparisons:
                comparison_inputs = _inputs(comparison)
                if not comparison_inputs:
                    continue
                check_address, check_index = _op_location(comparison)
                check = {
                    "id": _op_id("check", comparison),
                    "address": check_address,
                    "pcodeIndex": check_index,
                    "operation": _opcode(comparison),
                    "operator": COMPARISON_OPERATORS[_opcode(comparison)],
                    "left": tracer.value(comparison_inputs[0]),
                    "right": (
                        tracer.value(comparison_inputs[1])
                        if len(comparison_inputs) > 1
                        else None
                    ),
                    "branch": {
                        "address": branch_address,
                        "pcodeIndex": branch_index,
                        "target": branch_target,
                    },
                }
                checks.append(check)
        else:
            size = _safe_size(condition)
            checks.append(
                {
                    "id": _op_id("check", branch),
                    "address": branch_address,
                    "pcodeIndex": branch_index,
                    "operation": "CBRANCH",
                    "operator": "nonzero",
                    "left": tracer.value(condition),
                    "right": {
                        "size": size,
                        "origins": [
                            {
                                "kind": "constant",
                                "value": "0x0",
                                "size": size,
                            }
                        ],
                    },
                    "branch": {
                        "address": branch_address,
                        "pcodeIndex": branch_index,
                        "target": branch_target,
                    },
                }
            )

    returns: list[dict[str, Any]] = []
    for op in operations:
        if _opcode(op) != "RETURN":
            continue
        address, pcode_index = _op_location(op)
        op_inputs = _inputs(op)
        returns.append(
            {
                "id": _op_id("return", op),
                "address": address,
                "pcodeIndex": pcode_index,
                "values": [
                    {
                        "index": index - 1,
                        **tracer.value(op_inputs[index]),
                    }
                    for index in range(1, len(op_inputs))
                ],
            }
        )

    flows: list[dict[str, Any]] = []

    def append_flows(origins: list[dict[str, Any]], sink: dict[str, Any]) -> None:
        for source in _source_origins(origins):
            flows.append({"source": source, "sink": sink})

    for call in calls:
        target = call["target"]
        if target["kind"] == "indirect" and target.get("value") is not None:
            append_flows(
                target["value"]["origins"],
                {
                    "kind": "call_target",
                    "callId": call["id"],
                    "address": call["address"],
                },
            )
        for argument in call["arguments"]:
            append_flows(
                argument["origins"],
                {
                    "kind": "call_argument",
                    "callId": call["id"],
                    "address": call["address"],
                    "target": target,
                    "argument": argument["index"],
                },
            )

    for check in checks:
        for side in ("left", "right"):
            value = check.get(side)
            if value is None:
                continue
            append_flows(
                value["origins"],
                {
                    "kind": "check",
                    "checkId": check["id"],
                    "address": check["address"],
                    "side": side,
                    "operator": check["operator"],
                    "branchAddress": check["branch"]["address"],
                },
            )

    for return_record in returns:
        for value in return_record["values"]:
            append_flows(
                value["origins"],
                {
                    "kind": "return",
                    "returnId": return_record["id"],
                    "address": return_record["address"],
                    "value": value["index"],
                },
            )

    if tracer.truncated_traces:
        unresolved.append(
            {
                "kind": "trace_limit",
                "count": tracer.truncated_traces,
                "maximumDepth": tracer.max_depth,
            }
        )

    calls.sort(key=lambda call: (call["address"], call["pcodeIndex"], call["id"]))
    checks.sort(
        key=lambda check: (
            check["address"],
            check["pcodeIndex"],
            check["branch"]["address"],
            check["id"],
        )
    )
    returns.sort(
        key=lambda record: (
            record["address"],
            record["pcodeIndex"],
            record["id"],
        )
    )

    return {
        "schemaVersion": DATA_FLOW_SCHEMA_VERSION,
        "status": "complete",
        "function": {
            "name": function_name,
            "address": function_address,
        },
        "parameters": parameters,
        "calls": calls,
        "checks": checks,
        "returns": returns,
        "flows": _deduplicate(flows),
        "unresolved": unresolved,
    }


def flow_counts(flow: dict[str, Any]) -> dict[str, int]:
    calls = flow.get("calls") or []
    return {
        "calls": len(calls),
        "indirect_calls": sum(
            1 for call in calls if call.get("target", {}).get("kind") == "indirect"
        ),
        "checks": len(flow.get("checks") or []),
        "returns": len(flow.get("returns") or []),
        "flows": len(flow.get("flows") or []),
        "unresolved": len(flow.get("unresolved") or []),
    }
