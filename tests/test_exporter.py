import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from ghidra_no_mcp.exporter import (
    DIAGNOSTICS_FILENAME,
    GhidraExporter,
    classify_decompile_result,
)


class FakeDecompileResult:
    def __init__(
        self,
        completed,
        message="",
        failed_to_start=False,
        decompiled_function=None,
        high_function=None,
    ):
        self.completed = completed
        self.message = message
        self.failed_to_start = failed_to_start
        self.decompiled_function = decompiled_function
        self.high_function = high_function

    def decompileCompleted(self):
        return self.completed

    def getErrorMessage(self):
        return self.message

    def failedToStart(self):
        return self.failed_to_start

    def getDecompiledFunction(self):
        return self.decompiled_function

    def getHighFunction(self):
        return self.high_function


class FakeDecompiledFunction:
    def __init__(self, code):
        self.code = code

    def getC(self):
        return self.code


class FakeLocalSymbolMap:
    def getNumParams(self):
        return 0


class FakeHighFunction:
    def getPcodeOps(self):
        return iter(())

    def getLocalSymbolMap(self):
        return FakeLocalSymbolMap()


class FakeBrokenHighFunction:
    def getPcodeOps(self):
        raise RuntimeError("broken High P-code fixture")


class FakeDecompiler:
    def __init__(self, result):
        self.result = result

    def decompileFunction(self, _func, _timeout, _monitor):
        return self.result


class FakeInstruction:
    def __init__(self, address, raw, text):
        self.address = address
        self.raw = raw
        self.text = text

    def getAddress(self):
        return self.address

    def getBytes(self):
        return self.raw

    def __str__(self):
        return self.text


class FakeFunction:
    def __init__(self, name, address, instructions, *, external=False, thunk=False):
        self.name = name
        self.address = address
        self.instructions = instructions
        self.external = external
        self.thunk = thunk

    def getName(self):
        return self.name

    def getEntryPoint(self):
        return self.address

    def getBody(self):
        return self.instructions

    def isExternal(self):
        return self.external

    def isThunk(self):
        return self.thunk


class FakeFunctionManager:
    def __init__(self, functions):
        self.functions = functions

    def getFunctions(self, _forward):
        return list(self.functions)


class FakeListing:
    def getInstructions(self, body, _forward):
        return iter(body)


class FakeCompilerSpec:
    def getCompilerSpecID(self):
        return "default"


class FakeProgram:
    def __init__(self, functions):
        self.functions = functions

    def getFunctionManager(self):
        return FakeFunctionManager(self.functions)

    def getListing(self):
        return FakeListing()

    def getName(self):
        return "fixture"

    def getLanguageID(self):
        return "x86:LE:64:default"

    def getCompilerSpec(self):
        return FakeCompilerSpec()

    def getExecutableFormat(self):
        return "Portable Executable (PE)"

    def getImageBase(self):
        return "00400000"


class RecordingExporter(GhidraExporter):
    def __init__(self, program):
        super().__init__(
            program,
            skip_memory=True,
            skip_strings=True,
            skip_imports=True,
            skip_exports=True,
        )
        self.calls = []

    def analyze(self):
        raise AssertionError("export_preanalyzed must not run analysis")

    def _build_call_info(self):
        self.calls.append("build-call-info")
        return {}

    def export_call_graph(self, _output_dir):
        self.calls.append("call-graph")

    def export_functions(self, _output_dir):
        self.calls.append("functions")
        self.stats["exported"] = 1
        self._decompile_records.append(
            {
                "address": "00401000",
                "name": "main",
                "status": "exported",
            }
        )

    def export_disassembly(self, _output_dir):
        self.calls.append("disassembly")
        self.stats["disassembly"] = {
            "attempted": 1,
            "exported": 1,
            "failed": 0,
            "external_skipped": 0,
            "instruction_count": 1,
            "instruction_bytes": 1,
        }
        self._disassembly_records.append(
            {
                "address": "00401000",
                "name": "main",
                "status": "exported",
                "instructionCount": 1,
                "instructionBytes": 1,
            }
        )

    def export_sections(self, _output_dir):
        self.calls.append("sections")

    def export_triage(self, _output_dir):
        self.calls.append("triage")


class DecompileResultTests(unittest.TestCase):
    def test_completed_result_keeps_warning(self):
        completed, message = classify_decompile_result(
            FakeDecompileResult(True, "prototype recovery warning")
        )

        self.assertTrue(completed)
        self.assertEqual(message, "prototype recovery warning")

    def test_incomplete_result_uses_error(self):
        completed, message = classify_decompile_result(
            FakeDecompileResult(False, "process timeout")
        )

        self.assertFalse(completed)
        self.assertEqual(message, "process timeout")

    def test_failed_start_has_specific_fallback(self):
        completed, message = classify_decompile_result(
            FakeDecompileResult(False, failed_to_start=True)
        )

        self.assertFalse(completed)
        self.assertEqual(message, "decompiler executable failed to start")

    def test_completed_warning_still_writes_decompiled_output(self):
        task_module = types.ModuleType("ghidra.util.task")
        task_module.TaskMonitor = types.SimpleNamespace(DUMMY=object())
        result = FakeDecompileResult(
            True,
            "prototype recovery warning",
            decompiled_function=FakeDecompiledFunction("void main(void) {}"),
            high_function=FakeHighFunction(),
        )
        exporter = GhidraExporter(FakeProgram([]))
        exporter._thread_decompiler = lambda: FakeDecompiler(result)

        with tempfile.TemporaryDirectory() as tmp:
            decompile_dir = Path(tmp)
            with patch.dict(
                sys.modules,
                {
                    "ghidra": types.ModuleType("ghidra"),
                    "ghidra.util": types.ModuleType("ghidra.util"),
                    "ghidra.util.task": task_module,
                },
            ):
                record = exporter._decompile_one(
                    (object(), "00401000", "main"),
                    decompile_dir,
                )
            output = (decompile_dir / "main_00401000.c").read_text()
            flow = json.loads((decompile_dir / "main_00401000.flow.json").read_text())

        self.assertEqual(
            record,
            (
                "exported",
                "00401000",
                "main",
                "",
                "prototype recovery warning",
                {
                    "status": "exported",
                    "file": "decompile/main_00401000.flow.json",
                    "counts": {
                        "calls": 0,
                        "indirect_calls": 0,
                        "checks": 0,
                        "returns": 0,
                        "flows": 0,
                        "unresolved": 0,
                    },
                },
            ),
        )
        self.assertIn("void main(void)", output)
        self.assertEqual(flow["status"], "complete")

    def test_flow_failure_does_not_discard_valid_c_output(self):
        task_module = types.ModuleType("ghidra.util.task")
        task_module.TaskMonitor = types.SimpleNamespace(DUMMY=object())
        result = FakeDecompileResult(
            True,
            decompiled_function=FakeDecompiledFunction("void main(void) {}"),
            high_function=FakeBrokenHighFunction(),
        )
        exporter = GhidraExporter(FakeProgram([]))
        exporter._thread_decompiler = lambda: FakeDecompiler(result)

        with tempfile.TemporaryDirectory() as tmp:
            decompile_dir = Path(tmp)
            with patch.dict(
                sys.modules,
                {
                    "ghidra": types.ModuleType("ghidra"),
                    "ghidra.util": types.ModuleType("ghidra.util"),
                    "ghidra.util.task": task_module,
                },
            ):
                record = exporter._decompile_one(
                    (object(), "00401000", "main"),
                    decompile_dir,
                )
            c_output = (decompile_dir / "main_00401000.c").read_text()
            flow = json.loads((decompile_dir / "main_00401000.flow.json").read_text())

        self.assertEqual(record[0], "exported")
        self.assertEqual(record[5]["status"], "failed")
        self.assertIn("void main(void)", c_output)
        self.assertEqual(flow["status"], "failed")
        self.assertIn("broken High P-code fixture", flow["error"])


class DisassemblyTests(unittest.TestCase):
    def test_exports_every_internal_function_including_thunks(self):
        regular = FakeFunction(
            "main.worker",
            "ram:00401000",
            [FakeInstruction("00401000", [-1, 0x10], "MOV RAX,RBX")],
        )
        thunk = FakeFunction(
            "jump_thunk",
            "ram:00402000",
            [FakeInstruction("00402000", [0xEB, 0x01], "JMP 00402003")],
            thunk=True,
        )
        external = FakeFunction(
            "KERNEL32.dll::Sleep",
            "EXTERNAL:1",
            [],
            external=True,
        )
        exporter = GhidraExporter(FakeProgram([regular, thunk, external]))
        exporter.functions = [regular, thunk, external]

        with tempfile.TemporaryDirectory() as tmp:
            exporter.export_disassembly(Path(tmp))
            files = sorted((Path(tmp) / "disassembly").glob("*.asm"))
            contents = [path.read_text() for path in files]

        self.assertEqual(len(files), 2)
        self.assertTrue(any("main.worker" in content for content in contents))
        self.assertTrue(any("jump_thunk" in content for content in contents))
        self.assertTrue(any("ff 10" in content for content in contents))
        self.assertEqual(exporter.stats["disassembly"]["attempted"], 2)
        self.assertEqual(exporter.stats["disassembly"]["exported"], 2)
        self.assertEqual(exporter.stats["disassembly"]["external_skipped"], 1)

    def test_function_without_instructions_is_reported_failed(self):
        empty = FakeFunction("empty", "00401000", [])
        exporter = GhidraExporter(FakeProgram([empty]))
        exporter.functions = [empty]

        with tempfile.TemporaryDirectory() as tmp:
            exporter.export_disassembly(Path(tmp))

        self.assertEqual(exporter.stats["disassembly"]["failed"], 1)
        self.assertEqual(
            exporter._disassembly_records[0]["error"],
            "function body contains no defined instructions",
        )


class PreanalyzedExportTests(unittest.TestCase):
    def test_public_preanalyzed_export_does_not_invoke_analysis(self):
        main = FakeFunction(
            "main",
            "00401000",
            [FakeInstruction("00401000", [0xC3], "RET")],
        )
        exporter = RecordingExporter(FakeProgram([main]))

        with tempfile.TemporaryDirectory() as tmp:
            stats = exporter.export_preanalyzed(
                Path(tmp),
                analysis_log="analysis supplied by caller",
            )
            diagnostics = json.loads((Path(tmp) / DIAGNOSTICS_FILENAME).read_text())

        self.assertEqual(
            exporter.calls,
            [
                "build-call-info",
                "call-graph",
                "functions",
                "disassembly",
                "sections",
                "triage",
            ],
        )
        self.assertEqual(stats["artifact_coverage"], 1.0)
        self.assertEqual(diagnostics["status"], "complete")
        self.assertFalse(diagnostics["analysis"]["performedByExporter"])
        self.assertEqual(
            diagnostics["analysis"]["logTail"],
            "analysis supplied by caller",
        )


if __name__ == "__main__":
    unittest.main()
