import unittest

from ghidra_no_mcp.data_flow import extract_function_flow, flow_counts


class FakeSequenceNumber:
    def __init__(self, target, time=0):
        self.target = target
        self.time = time

    def getTarget(self):
        return self.target

    def getTime(self):
        return self.time


class FakeParameter:
    def __init__(self, slot, name, size=8, data_type="undefined8"):
        self.slot = slot
        self.name = name
        self.size = size
        self.data_type = data_type
        self.representative = None

    def getSlot(self):
        return self.slot

    def getName(self):
        return self.name

    def getDataType(self):
        return self.data_type

    def getRepresentative(self):
        return self.representative


class FakeVarnode:
    def __init__(
        self,
        address,
        *,
        size=8,
        constant=None,
        high=None,
        input_=False,
        persistent=False,
    ):
        self.address = address
        self.size = size
        self.constant = constant
        self.high = high
        self.input_ = input_
        self.persistent = persistent
        self.defining_op = None

    def getAddress(self):
        return self.address

    def getSize(self):
        return self.size

    def getOffset(self):
        return self.constant or 0

    def getDef(self):
        return self.defining_op

    def getHigh(self):
        return self.high

    def isConstant(self):
        return self.constant is not None

    def isInput(self):
        return self.input_

    def isPersistent(self):
        return self.persistent


class FakePcodeOp:
    def __init__(self, mnemonic, address, inputs, output=None, time=0):
        self.mnemonic = mnemonic
        self.seqnum = FakeSequenceNumber(address, time)
        self.inputs = inputs
        self.output = output
        if output is not None:
            output.defining_op = self

    def getMnemonic(self):
        return self.mnemonic

    def getSeqnum(self):
        return self.seqnum

    def getNumInputs(self):
        return len(self.inputs)

    def getInput(self, index):
        return self.inputs[index]

    def getOutput(self):
        return self.output


class FakeLocalSymbolMap:
    def __init__(self, parameters):
        self.parameters = parameters

    def getNumParams(self):
        return len(self.parameters)

    def getParam(self, index):
        return self.parameters[index]


class FakeHighFunction:
    def __init__(self, operations, parameters):
        self.operations = operations
        self.symbol_map = FakeLocalSymbolMap(parameters)

    def getPcodeOps(self):
        return iter(self.operations)

    def getLocalSymbolMap(self):
        return self.symbol_map


class DataFlowTests(unittest.TestCase):
    def test_extracts_call_result_parameter_check_and_return_flows(self):
        parameter = FakeParameter(0, "candidate", size=1, data_type="byte")
        parameter_node = FakeVarnode(
            "register:AL",
            size=1,
            high=parameter,
            input_=True,
        )
        parameter.representative = parameter_node

        source_target = FakeVarnode("00402000", constant=0x402000)
        source_result = FakeVarnode("unique:100", size=1)
        source_call = FakePcodeOp(
            "CALL",
            "00401000",
            [source_target],
            source_result,
        )

        copied_result = FakeVarnode("unique:101", size=1)
        copy = FakePcodeOp(
            "COPY",
            "00401008",
            [source_result],
            copied_result,
        )

        validate_target = FakeVarnode("00403000", constant=0x403000)
        validate_call = FakePcodeOp(
            "CALL",
            "00401010",
            [validate_target, copied_result],
        )

        expected = FakeVarnode("const:82", size=1, constant=0x82)
        comparison_result = FakeVarnode("unique:102", size=1)
        comparison = FakePcodeOp(
            "INT_EQUAL",
            "00401020",
            [parameter_node, expected],
            comparison_result,
        )
        branch_target = FakeVarnode("00401040", constant=0x401040)
        branch = FakePcodeOp(
            "CBRANCH",
            "00401024",
            [branch_target, comparison_result],
        )
        return_target = FakeVarnode("register:RA", size=8, input_=True)
        return_op = FakePcodeOp(
            "RETURN",
            "00401030",
            [return_target, copied_result],
        )

        names = {
            "00402000": "source",
            "00403000": "validate",
        }

        def resolve(target):
            address = str(target.getAddress())
            return {
                "address": address,
                "name": names[address],
                "external": False,
            }

        flow = extract_function_flow(
            FakeHighFunction(
                [
                    source_call,
                    copy,
                    validate_call,
                    comparison,
                    branch,
                    return_op,
                ],
                [parameter],
            ),
            function_name="main",
            function_address="00401000",
            resolve_direct_call=resolve,
        )

        self.assertEqual(flow["status"], "complete")
        self.assertEqual(flow["parameters"][0]["name"], "candidate")
        self.assertEqual(flow["calls"][0]["target"]["name"], "source")
        self.assertEqual(flow["calls"][1]["target"]["name"], "validate")
        argument_origins = flow["calls"][1]["arguments"][0]["origins"]
        self.assertEqual(argument_origins[0]["kind"], "call_result")
        self.assertEqual(argument_origins[0]["target"]["name"], "source")
        self.assertEqual(flow["checks"][0]["operator"], "==")
        self.assertEqual(
            flow["checks"][0]["left"]["origins"][0]["kind"],
            "parameter",
        )
        self.assertEqual(
            flow["checks"][0]["right"]["origins"][0]["value"],
            "0x82",
        )
        self.assertEqual(
            flow["returns"][0]["values"][0]["origins"][0]["kind"],
            "call_result",
        )

        sinks = {
            item["sink"]["kind"]
            for item in flow["flows"]
            if item["source"]["kind"] == "call_result"
        }
        self.assertEqual(sinks, {"call_argument", "return"})
        self.assertTrue(
            any(
                item["source"]["kind"] == "parameter"
                and item["sink"]["kind"] == "check"
                for item in flow["flows"]
            )
        )
        self.assertEqual(
            flow_counts(flow),
            {
                "calls": 2,
                "indirect_calls": 0,
                "checks": 1,
                "returns": 1,
                "flows": 3,
                "unresolved": 0,
            },
        )

    def test_branch_without_explicit_comparison_is_nonzero_check(self):
        source_target = FakeVarnode("00402000", constant=0x402000)
        source_result = FakeVarnode("unique:200", size=1)
        source_call = FakePcodeOp(
            "CALL",
            "00401000",
            [source_target],
            source_result,
        )
        branch_target = FakeVarnode("00401020", constant=0x401020)
        branch = FakePcodeOp(
            "CBRANCH",
            "00401008",
            [branch_target, source_result],
        )

        flow = extract_function_flow(
            FakeHighFunction([source_call, branch], []),
            function_name="main",
            function_address="00401000",
        )

        self.assertEqual(flow["checks"][0]["operator"], "nonzero")
        self.assertEqual(
            flow["checks"][0]["left"]["origins"][0]["kind"],
            "call_result",
        )
        self.assertEqual(flow["flows"][0]["sink"]["kind"], "check")

    def test_records_indirect_call_target_and_argument_sources(self):
        target_parameter = FakeParameter(0, "callback")
        target_node = FakeVarnode(
            "register:X8",
            high=target_parameter,
            input_=True,
        )
        target_parameter.representative = target_node
        argument_parameter = FakeParameter(1, "context")
        argument_node = FakeVarnode(
            "register:X0",
            high=argument_parameter,
            input_=True,
        )
        argument_parameter.representative = argument_node
        result_node = FakeVarnode("unique:300", size=4)
        indirect_call = FakePcodeOp(
            "CALLIND",
            "00401000",
            [target_node, argument_node],
            result_node,
        )

        flow = extract_function_flow(
            FakeHighFunction(
                [indirect_call],
                [target_parameter, argument_parameter],
            ),
            function_name="dispatch",
            function_address="00401000",
        )

        self.assertEqual(flow["calls"][0]["target"]["kind"], "indirect")
        self.assertEqual(
            flow["calls"][0]["target"]["value"]["origins"][0]["name"],
            "callback",
        )
        self.assertEqual(flow["unresolved"][0]["kind"], "indirect_call")
        self.assertEqual(
            {item["sink"]["kind"] for item in flow["flows"]},
            {"call_target", "call_argument"},
        )
        self.assertEqual(flow_counts(flow)["indirect_calls"], 1)


if __name__ == "__main__":
    unittest.main()
