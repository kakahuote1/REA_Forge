"""Bounded host-static Python facade for IDALib work-IDB automation.

This is deliberately not a softened version of ``py_eval``.  The caller gets
no IDAPython modules, imports, filesystem, process, network or reflection
surface.  A small AST language can only call this module's fixed ``db`` facade.
Raw IDAPython remains an explicit VM-domain capability.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from typing import Annotated, Any, TypedDict

import ida_funcs
import ida_loader
import ida_name
import idaapi
import idc



_MAX_CODE_CHARS = 12_000
_MAX_AST_NODES = 600
_MAX_LOOP_STEPS = 256
_MAX_QUERY_ROWS = 64
_MAX_WRITES = 32
_MAX_COMMENT_CHARS = 1_024
_MAX_TYPE_CHARS = 512
_MAX_RESULT_CHARS = 12_000
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_BUILTINS = frozenset({"abs", "bool", "dict", "enumerate", "int", "len", "list", "max", "min", "range", "sorted", "str", "sum"})
_SAFE_METHODS = frozenset({"append", "endswith", "extend", "get", "items", "join", "keys", "lower", "pop", "replace", "sort", "split", "startswith", "strip", "upper", "values"})
_FACADE_METHODS = frozenset({"comment", "functions", "lookup", "rename", "save", "set_type", "status"})


class SafePythonResult(TypedDict, total=False):
    ok: bool
    result: Any
    writes: list[dict[str, str]]
    loop_steps: int
    error: str


class SafePythonError(ValueError):
    """The submitted restricted program violates the host-static contract."""


def _json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        raise SafePythonError("result nesting exceeds the safe facade limit")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise SafePythonError("integer result is outside the JSON-safe range")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_RESULT_CHARS:
            raise SafePythonError("string result exceeds the safe facade limit")
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_QUERY_ROWS:
            raise SafePythonError("list result exceeds the safe facade limit")
        return [_json_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > _MAX_QUERY_ROWS:
            raise SafePythonError("map result exceeds the safe facade limit")
        return {str(key): _json_value(item, depth=depth + 1) for key, item in value.items()}
    raise SafePythonError(f"result type is not JSON-safe: {type(value).__name__}")


def _as_address(value: str | int) -> int:
    if isinstance(value, bool):
        raise SafePythonError("address must be a string or integer")
    try:
        ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as error:
        raise SafePythonError("address must be a valid integer or 0x-prefixed string") from error
    if ea == idaapi.BADADDR or idaapi.getseg(ea) is None:
        raise SafePythonError("address is not mapped in the active work IDB")
    return ea


@dataclass
class _Facade:
    writes: list[dict[str, str]] = field(default_factory=list)

    def _admit_write(self) -> None:
        if len(self.writes) >= _MAX_WRITES:
            raise SafePythonError("safe facade write budget exceeded")

    def _record(self, kind: str, ea: int, detail: str) -> None:
        if len(self.writes) >= _MAX_WRITES:
            raise SafePythonError("safe facade write budget exceeded")
        self.writes.append({"kind": kind, "addr": hex(ea), "detail": detail})

    @staticmethod
    def _function_row(func: Any) -> dict[str, str]:
        return {"addr": hex(func.start_ea), "name": ida_name.get_name(func.start_ea) or idaapi.get_func_name(func.start_ea) or ""}

    def functions(self, contains: str = "", limit: int = 32) -> list[dict[str, str]]:
        if not isinstance(contains, str) or len(contains) > 128:
            raise SafePythonError("function filter must be a short string")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_QUERY_ROWS:
            raise SafePythonError("function limit must be between 1 and 64")
        rows: list[dict[str, str]] = []
        func = ida_funcs.get_next_func(0)
        while func is not None and len(rows) < limit:
            row = self._function_row(func)
            if contains.casefold() in row["name"].casefold():
                rows.append(row)
            func = ida_funcs.get_next_func(func.start_ea + 1)
        return rows

    def lookup(self, name_or_address: str | int) -> dict[str, str] | None:
        if isinstance(name_or_address, str) and not name_or_address.startswith("0x") and not name_or_address.isdecimal():
            ea = ida_name.get_name_ea(idaapi.BADADDR, name_or_address)
            if ea == idaapi.BADADDR:
                return None
        else:
            ea = _as_address(name_or_address)
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return self._function_row(func)

    def rename(self, address: str | int, name: str) -> bool:
        self._admit_write()
        ea = _as_address(address)
        if not isinstance(name, str) or not _SAFE_IDENTIFIER.fullmatch(name):
            raise SafePythonError("new function name is not a valid bounded identifier")
        if ida_funcs.get_func(ea) is None:
            raise SafePythonError("rename facade only accepts a function address")
        existing = ida_name.get_name_ea(idaapi.BADADDR, name)
        if existing != idaapi.BADADDR and existing != ea:
            raise SafePythonError("new function name is already used")
        if not ida_name.set_name(ea, name, ida_name.SN_CHECK):
            raise SafePythonError("IDA rejected the requested function name")
        self._record("rename", ea, name)
        return True

    def comment(self, address: str | int, text: str) -> bool:
        self._admit_write()
        ea = _as_address(address)
        if ida_funcs.get_func(ea) is None:
            raise SafePythonError("comment facade only accepts a function address")
        if not isinstance(text, str) or not text.strip() or len(text) > _MAX_COMMENT_CHARS:
            raise SafePythonError("comment must be a non-empty string up to 1024 characters")
        if not bool(idc.set_cmt(ea, text, 0)):
            raise SafePythonError("IDA rejected the requested function comment")
        self._record("comment", ea, text)
        return True

    def set_type(self, address: str | int, signature: str) -> bool:
        self._admit_write()
        ea = _as_address(address)
        if ida_funcs.get_func(ea) is None:
            raise SafePythonError("type facade only accepts a function address")
        if not isinstance(signature, str) or not signature.strip() or len(signature) > _MAX_TYPE_CHARS:
            raise SafePythonError("function signature must be a non-empty string up to 512 characters")
        if "#" in signature or "\0" in signature:
            raise SafePythonError("external includes and preprocessor directives are unavailable")
        if not bool(idc.SetType(ea, signature)):
            raise SafePythonError("IDA rejected the requested function signature")
        self._record("set_type", ea, signature)
        return True

    def save(self) -> bool:
        self._admit_write()
        if not bool(ida_loader.save_database(None, 0)):
            raise SafePythonError("IDA could not save the active work IDB")
        self._record("save", 0, "current_work_idb")
        return True

    def status(self) -> dict[str, int]:
        return {"max_query_rows": _MAX_QUERY_ROWS, "max_writes": _MAX_WRITES, "max_loop_steps": _MAX_LOOP_STEPS}


class _Validator(ast.NodeVisitor):
    """Allow only a closed expression/statement subset over JSON values and db."""

    def __init__(self) -> None:
        self.names = set(_SAFE_BUILTINS) | {"db", "result"}

    def validate(self, tree: ast.Module) -> None:
        if sum(1 for _ in ast.walk(tree)) > _MAX_AST_NODES:
            raise SafePythonError("program AST exceeds the safe facade limit")
        self.visit(tree)

    def generic_visit(self, node: ast.AST) -> None:
        raise SafePythonError(f"syntax is not available in the host-safe facade: {type(node).__name__}")

    def visit_Module(self, node: ast.Module) -> None:
        if not node.body:
            raise SafePythonError("program must contain at least one statement")
        for statement in node.body:
            self.visit(statement)

    def _target(self, node: ast.AST) -> None:
        if isinstance(node, ast.Name) and not node.id.startswith("__") and node.id not in {"_safe_tick", "db", *_SAFE_BUILTINS}:
            self.names.add(node.id)
            return
        if isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                self._target(element)
            return
        raise SafePythonError("assignments may only target local variable names")

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._target(target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        if not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)):
            raise SafePythonError("augmented operator is not available in the host-safe facade")
        if not isinstance(node.target, ast.Name):
            raise SafePythonError("augmented assignment may only use a local variable")

    def visit_Expr(self, node: ast.Expr) -> None:
        self.visit(node.value)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._target(node.target)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_Break(self, node: ast.Break) -> None:
        return

    def visit_Continue(self, node: ast.Continue) -> None:
        return

    def visit_Pass(self, node: ast.Pass) -> None:
        return

    def visit_Name(self, node: ast.Name) -> None:
        if node.id.startswith("__") or node.id not in self.names:
            raise SafePythonError(f"name is not available in the host-safe facade: {node.id}")

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, (str, int, bool, type(None))) or (isinstance(node.value, str) and len(node.value) > _MAX_COMMENT_CHARS):
            raise SafePythonError("only bounded JSON scalar literals are allowed")

    def visit_List(self, node: ast.List) -> None:
        if len(node.elts) > _MAX_QUERY_ROWS:
            raise SafePythonError("list literal exceeds the safe facade limit")
        for item in node.elts:
            self.visit(item)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self.visit_List(ast.List(elts=node.elts))

    def visit_Dict(self, node: ast.Dict) -> None:
        if len(node.keys) > _MAX_QUERY_ROWS or any(key is None for key in node.keys):
            raise SafePythonError("map literal exceeds the safe facade limit")
        for key, value in zip(node.keys, node.values, strict=True):
            self.visit(key)
            self.visit(value)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.visit(node.value)
        self.visit(node.slice)

    def visit_Slice(self, node: ast.Slice) -> None:
        for item in (node.lower, node.upper, node.step):
            if item is not None:
                self.visit(item)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if not isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)):
            raise SafePythonError("operator is not available in the host-safe facade")
        self.visit(node.left)
        self.visit(node.right)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if not isinstance(node.op, (ast.Not, ast.UAdd, ast.USub)):
            raise SafePythonError("unary operator is not available in the host-safe facade")
        self.visit(node.operand)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if not isinstance(node.op, (ast.And, ast.Or)):
            raise SafePythonError("boolean operator is not available")
        for value in node.values:
            self.visit(value)

    def visit_Compare(self, node: ast.Compare) -> None:
        if not all(isinstance(operator, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)) for operator in node.ops):
            raise SafePythonError("comparison operator is not available")
        self.visit(node.left)
        for comparator in node.comparators:
            self.visit(comparator)

    def visit_Call(self, node: ast.Call) -> None:
        if any(keyword.arg is None for keyword in node.keywords):
            raise SafePythonError("argument expansion is not available")
        if isinstance(node.func, ast.Name):
            if node.func.id not in _SAFE_BUILTINS:
                raise SafePythonError(f"call is not available in the host-safe facade: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith("__"):
                raise SafePythonError("dunder reflection is not available")
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "db":
                if node.func.attr not in _FACADE_METHODS:
                    raise SafePythonError(f"db method is not available: {node.func.attr}")
            elif node.func.attr not in _SAFE_METHODS:
                raise SafePythonError(f"value method is not available: {node.func.attr}")
            else:
                self.visit(node.func.value)
        else:
            raise SafePythonError("only fixed builtins, db methods and value methods may be called")
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)


class _LoopBudget(ast.NodeTransformer):
    """Inject a cheap deterministic step check at the start of every loop body."""

    @staticmethod
    def _tick() -> ast.Expr:
        return ast.Expr(value=ast.Call(func=ast.Name(id="_safe_tick", ctx=ast.Load()), args=[], keywords=[]))

    def visit_For(self, node: ast.For) -> ast.For:
        self.generic_visit(node)
        node.body.insert(0, self._tick())
        return node

    def visit_While(self, node: ast.While) -> ast.While:
        self.generic_visit(node)
        node.body.insert(0, self._tick())
        return node


def _bounded_range(*values: int) -> range:
    if not 1 <= len(values) <= 3 or any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise SafePythonError("range accepts one to three integer arguments")
    result = range(*values)
    if len(result) > _MAX_QUERY_ROWS:
        raise SafePythonError("range exceeds the safe facade limit")
    return result


def ida_python_safe_exec(
    code: Annotated[str, "Restricted host-static Python. Only local JSON values, bounded loops and db.{functions,lookup,rename,comment,set_type,save,status} are available."],
) -> SafePythonResult:
    """Execute bounded static-IDB automation without exposing raw IDAPython."""
    if not isinstance(code, str) or not code.strip() or len(code) > _MAX_CODE_CHARS:
        return {"ok": False, "error": "code must be a non-empty string up to 12000 characters"}
    try:
        tree = ast.parse(code, mode="exec")
        _Validator().validate(tree)
        tree = _LoopBudget().visit(tree)
        ast.fix_missing_locations(tree)
        facade = _Facade()
        loop_steps = 0

        def tick() -> None:
            nonlocal loop_steps
            loop_steps += 1
            if loop_steps > _MAX_LOOP_STEPS:
                raise SafePythonError("loop step budget exceeded")

        safe_globals = {
            "__builtins__": {
                "abs": abs, "bool": bool, "dict": dict, "enumerate": enumerate, "int": int,
                "len": len, "list": list, "max": max, "min": min, "range": _bounded_range,
                "sorted": sorted, "str": str, "sum": sum,
            },
            "db": facade,
            "_safe_tick": tick,
        }
        local_state: dict[str, Any] = {}
        exec(compile(tree, "<ida_python_safe_exec>", "exec"), safe_globals, local_state)
        result = _json_value(local_state.get("result", {"writes": facade.writes}))
        serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        if len(serialized) > _MAX_RESULT_CHARS:
            raise SafePythonError("serialized result exceeds the safe facade limit")
        return {"ok": True, "result": result, "writes": facade.writes, "loop_steps": loop_steps}
    except (SafePythonError, SyntaxError, ValueError, TypeError) as error:
        return {"ok": False, "error": str(error)}
    except Exception:
        return {"ok": False, "error": "safe facade execution failed"}
