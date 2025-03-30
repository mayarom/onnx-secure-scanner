import os
import re
import json
import onnx
from pathlib import Path
from uuid import UUID
from typing import Dict, List, Tuple, Any, Optional, Set
from base_scanner import Scanner


class ONNXScanner(Scanner):
    def __init__(self, model_path: Path, file_id: UUID):
        """Initialize ONNX scanner with model path and file ID"""
        super().__init__(model_path, file_id)

        # Known malicious domains (IOC - Indicators of Compromise)
        # Highly specific domains known for malicious activity
        self.malicious_domains = [
            "evil-domain.com", "ngrok.io", "burpcollaborator.net",
            "requestbin.net", "evil.site", "attacker.com"
        ]

        # Critical system files that shouldn't be accessed via path traversal
        # Focus on the most sensitive files to avoid false positives
        self.critical_files = [
            "etc/passwd", "etc/shadow", ".ssh/id_rsa", "id_rsa",
            ".ssh/authorized_keys", ".aws/credentials"
        ]

        # High-risk shell command operators (very specific indicators)
        self.shell_execution_patterns = [
            "| bash", "| sh", "; bash", "; sh",
            "| python -c", "; python -c", "&& python -c",
            "$(bash", "`bash", "$(sh", "`sh",
            "rm -rf /", "chmod +x"
        ]

        # Suspicious operator types that clearly indicate code execution
        # Very specific operator names that are definitely malicious
        self.malicious_operators = [
            "ShellExec", "RunCommand", "SystemCall", "Exec",
            "ScriptOp:run", "CommandExec"
        ]

        # Standard ONNX operators (comprehensive list to avoid false positives)
        self.standard_onnx_operators = {
            "Abs", "Acos", "Acosh", "Add", "And", "ArgMax", "ArgMin", "Asin", "Asinh",
            "Atan", "Atanh", "AveragePool", "BatchNormalization", "BitShift", "Cast",
            "Ceil", "Clip", "Compress", "Concat", "ConcatFromSequence", "Constant",
            "ConstantOfShape", "Conv", "ConvInteger", "ConvTranspose", "Cos", "Cosh",
            "CumSum", "DepthToSpace", "DequantizeLinear", "Det", "Div", "Dropout",
            "DynamicQuantizeLinear", "Einsum", "Elu", "Equal", "Erf", "Exp", "Expand",
            "EyeLike", "Flatten", "Floor", "GRU", "Gather", "GatherElements", "GatherND",
            "Gemm", "GlobalAveragePool", "GlobalLpPool", "GlobalMaxPool", "Gradient",
            "Greater", "GreaterOrEqual", "HardSigmoid", "Hardmax", "Identity", "If",
            "InstanceNormalization", "IsInf", "IsNaN", "LRN", "LSTM", "LeakyRelu",
            "Less", "LessOrEqual", "Log", "LogSoftmax", "Loop", "LpNormalization",
            "LpPool", "MatMul", "MatMulInteger", "Max", "MaxPool", "MaxRoiPool",
            "MaxUnpool", "Mean", "MeanVarianceNormalization", "Min", "Mod", "Mul",
            "Multinomial", "Neg", "NonMaxSuppression", "NonZero", "Not", "OneHot",
            "Or", "PRelu", "Pad", "Pow", "QLinearConv", "QLinearMatMul", "QuantizeLinear",
            "RNN", "RandomNormal", "RandomNormalLike", "RandomUniform", "RandomUniformLike",
            "Range", "Reciprocal", "ReduceL1", "ReduceL2", "ReduceLogSum", "ReduceLogSumExp",
            "ReduceMax", "ReduceMean", "ReduceMin", "ReduceProd", "ReduceSum", "ReduceSumSquare",
            "Relu", "Reshape", "Resize", "ReverseSequence", "RoiAlign", "Round", "Scan",
            "Scatter", "ScatterElements", "ScatterND", "Selu", "SequenceAt", "SequenceConstruct",
            "SequenceEmpty", "SequenceErase", "SequenceInsert", "SequenceLength", "Shape",
            "Shrink", "Sigmoid", "Sign", "Sin", "Sinh", "Size", "Slice", "Softmax",
            "Softplus", "Softsign", "SpaceToDepth", "Split", "SplitToSequence", "Sqrt",
            "Squeeze", "StringNormalizer", "Sub", "Sum", "Tan", "Tanh", "TfIdfVectorizer",
            "ThresholdedRelu", "Tile", "TopK", "Transpose", "Unique", "Unsqueeze", "Upsample",
            "Where", "Xor", "Celu", "DynamicSlice", "GreaterOrEqual", "LessOrEqual",
            "Trilu", "LayerNormalization", "GroupNormalization"
        }

        # Suspicious binary extensions (high-risk only)
        self.suspicious_extensions = [
            ".exe", ".bat", ".cmd", ".sh", ".ps1"
        ]

        # Initialize scan_results with the correct format
        self.scan_results = {"vulnerabilities": []}

    def add_vulnerability(self, vuln_type: str, description: str, evidence: str,
                          severity: str = "HIGH", certainty: str = "SUSPECTED") -> None:
        """Add a detected vulnerability to the scan_results dict with certainty level."""
        self.scan_results["vulnerabilities"].append({
            "type": vuln_type,
            "description": description,
            "evidence": evidence,
            "severity": severity,
            "certainty": certainty  # New field to indicate confidence level
        })

        # Mark as anomaly since we found a vulnerability
        self.is_anomaly = True

    def check_path_traversal(self, value: str) -> Tuple[bool, str, str]:
        """
        Check for path traversal attempts in a string value.
        Very strict checking to avoid false positives.
        """
        # Exact pattern matching using regex for path traversal
        path_traversal_pattern = r'\.\.\/+.*(?:' + '|'.join(re.escape(file) for file in self.critical_files) + ')'

        if re.search(path_traversal_pattern, value):
            # Identify which critical file is being targeted
            for critical_file in self.critical_files:
                if critical_file in value and "../" in value:
                    return True, f"Path traversal to critical file: {critical_file}", "PROVEN"

        return False, "", ""

    def check_shell_injection(self, value: str) -> Tuple[bool, str, str]:
        """
        Check for shell command injection in a string value.
        Uses very specific patterns to avoid false positives.
        """
        # Check for high-risk shell command patterns only
        for pattern in self.shell_execution_patterns:
            if pattern in value:
                # Additional verification to avoid false positives
                # Check for common shell command context
                shell_context = any(cmd in value for cmd in [
                    "curl ", "wget ", "bash ", "sh ", "python ", "perl ",
                    "chmod ", "rm -rf", "cat /", "nc -e", "/dev/tcp/"
                ])

                if shell_context:
                    return True, f"Shell command injection with execution: {pattern}", "PROVEN"

        return False, "", ""

    def check_suspicious_url(self, value: str) -> Tuple[bool, str, str]:
        """
        Check for suspicious URLs in a string value.
        Only flag as PROVEN if it contains a known malicious domain from IOC list
        AND has suspicious context.
        """
        if value.startswith("http://") or value.startswith("https://"):
            # Check against known malicious domains (IOC list)
            for domain in self.malicious_domains:
                if domain in value:
                    # Additional verification: check for suspicious URL parameters
                    suspicious_parameters = any(param in value for param in [
                        "cmd=", "exec=", "shell=", "command=", "payload=", "exploit="
                    ])

                    if suspicious_parameters:
                        return True, f"URL containing known malicious domain with suspicious parameters: {domain}", "PROVEN"
                    else:
                        # Domain is on block list but without malicious parameters
                        return True, f"URL containing known malicious domain: {domain}", "SUSPECTED"

        return False, "", ""

    def check_suspicious_extension(self, value: str) -> Tuple[bool, str, str]:
        """
        Check for suspicious file extensions in external data references.
        Only flags high-risk executable extensions.
        """
        if "location" in value.lower() or "external_data" in value.lower():
            for ext in self.suspicious_extensions:
                # Full pattern matching to avoid partial matches
                if value.lower().endswith(ext) or f"{ext} " in value.lower() or f"{ext}" in value.lower():
                    return True, f"External data with executable extension: {ext}", "PROVEN"

        return False, "", ""

    def check_suspicious_operator(self, op_type: str) -> Tuple[bool, str, str]:
        """
        Check if operator type is suspicious and may indicate code execution.
        PROVEN only for known malicious operators.
        """
        # If it's a standard ONNX operator, it's safe
        if op_type in self.standard_onnx_operators:
            return False, "", ""

        # Check for known malicious operators
        for op in self.malicious_operators:
            if op == op_type or f"{op}:" in op_type:
                return True, f"Custom operator with malicious name: {op_type}", "PROVEN"

        # Non-standard operator but no clearly malicious name pattern
        if "Exec" in op_type or "Shell" in op_type or "Command" in op_type or "System" in op_type:
            return True, f"Non-standard operator with suspicious name: {op_type}", "SUSPECTED"

        # Other non-standard operators are not reported to avoid false positives
        return False, "", ""

    def scan_string_value(self, field_name: str, value: str, context: str = "") -> None:
        """Scan a string value for multiple types of vulnerabilities with high precision."""
        if not value or not isinstance(value, str) or len(value.strip()) == 0:
            return

        # Path traversal check
        is_vuln, desc, certainty = self.check_path_traversal(value)
        if is_vuln:
            self.add_vulnerability(
                "PATH_TRAVERSAL",
                f"Path traversal detected in {field_name}: {desc}",
                f"{context} - {field_name}: {value}",
                "HIGH",
                certainty
            )

        # Shell injection check
        is_vuln, desc, certainty = self.check_shell_injection(value)
        if is_vuln:
            self.add_vulnerability(
                "SHELL_INJECTION",
                f"Shell command injection detected in {field_name}: {desc}",
                f"{context} - {field_name}: {value}",
                "CRITICAL",
                certainty
            )

        # Suspicious URL check
        is_vuln, desc, certainty = self.check_suspicious_url(value)
        if is_vuln:
            self.add_vulnerability(
                "MALICIOUS_URL",
                f"Malicious URL detected in {field_name}: {desc}",
                f"{context} - {field_name}: {value}",
                "HIGH",
                certainty
            )

        # Suspicious extension check
        is_vuln, desc, certainty = self.check_suspicious_extension(value)
        if is_vuln:
            self.add_vulnerability(
                "SUSPICIOUS_EXTERNAL_DATA",
                f"Suspicious external data reference detected: {desc}",
                f"{context} - {field_name}: {value}",
                "HIGH",
                certainty
            )

    def weakness_scan(self) -> Dict[str, Any]:
        """
        Implementation of the abstract method for scanning weaknesses in ONNX models.
        Each vulnerability detected is added to the scan_results dict.
        High precision scanning to minimize false positives.
        """
        try:
            # Load the ONNX model
            model = onnx.load(self.model_path)

            # Check model metadata properties
            if model.metadata_props:
                for prop in model.metadata_props:
                    if hasattr(prop, 'key') and hasattr(prop, 'value'):
                        key = prop.key
                        value = prop.value
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='ignore')
                        self.scan_string_value(key, value, "Model Metadata")

            # Check graph name and doc_string
            if model.graph:
                if model.graph.name:
                    self.scan_string_value("graph_name", model.graph.name, "Graph")

                if model.graph.doc_string:
                    doc_string = model.graph.doc_string
                    if isinstance(doc_string, bytes):
                        doc_string = doc_string.decode('utf-8', errors='ignore')
                    self.scan_string_value("doc_string", doc_string, "Graph")

                # Check nodes for suspicious operators and attributes
                for node_idx, node in enumerate(model.graph.node):
                    # Check operator type
                    if node.op_type:
                        is_vuln, desc, certainty = self.check_suspicious_operator(node.op_type)
                        if is_vuln:
                            self.add_vulnerability(
                                "SUSPICIOUS_OPERATOR",
                                f"Suspicious operator detected: {desc}",
                                f"Node[{node_idx}] - op_type: {node.op_type}",
                                "HIGH",
                                certainty
                            )

                    # Check node name and doc_string
                    if node.name:
                        self.scan_string_value("node_name", node.name, f"Node[{node_idx}]")

                    if node.doc_string:
                        doc_string = node.doc_string
                        if isinstance(doc_string, bytes):
                            doc_string = doc_string.decode('utf-8', errors='ignore')
                        self.scan_string_value("doc_string", doc_string, f"Node[{node_idx}]")

                    # Check node attributes
                    for attr in node.attribute:
                        if attr.name:
                            self.scan_string_value("attribute_name", attr.name, f"Node[{node_idx}]")

                        # Check string attributes
                        if attr.type == onnx.AttributeProto.STRING and attr.s:
                            attr_value = attr.s.decode('utf-8', errors='ignore') if isinstance(attr.s, bytes) else str(
                                attr.s)
                            self.scan_string_value(f"attribute[{attr.name}]", attr_value, f"Node[{node_idx}]")

                # Check initializers
                for init_idx, initializer in enumerate(model.graph.initializer):
                    if initializer.name:
                        self.scan_string_value("initializer_name", initializer.name, f"Initializer[{init_idx}]")

                    # Check for external data references
                    if hasattr(initializer, 'has_external_data') and initializer.has_external_data:
                        for key, value in initializer.external_data:
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='ignore')
                            self.scan_string_value(f"external_data[{key}]", value, f"Initializer[{init_idx}]")

                # Check inputs and outputs
                for input_idx, input_info in enumerate(model.graph.input):
                    if input_info.name:
                        self.scan_string_value("input_name", input_info.name, f"Input[{input_idx}]")

                    if input_info.doc_string:
                        doc_string = input_info.doc_string
                        if isinstance(doc_string, bytes):
                            doc_string = doc_string.decode('utf-8', errors='ignore')
                        self.scan_string_value("input_doc_string", doc_string, f"Input[{input_idx}]")

                for output_idx, output_info in enumerate(model.graph.output):
                    if output_info.name:
                        self.scan_string_value("output_name", output_info.name, f"Output[{output_idx}]")

                    if output_info.doc_string:
                        doc_string = output_info.doc_string
                        if isinstance(doc_string, bytes):
                            doc_string = doc_string.decode('utf-8', errors='ignore')
                        self.scan_string_value("output_doc_string", doc_string, f"Output[{output_idx}]")

            # Filter out suspected vulnerabilities if requested
            # Uncomment this to only report PROVEN vulnerabilities
            # self.scan_results["vulnerabilities"] = [v for v in self.scan_results["vulnerabilities"]
            #                                       if v["certainty"] == "PROVEN"]

            return self.scan_results

        except Exception as e:
            self.add_vulnerability(
                "SCANNING_ERROR",
                f"Error during ONNX weakness scanning: {str(e)}",
                str(e),
                "MEDIUM",
                "PROVEN"
            )
            return self.scan_results

    def metadata_extractor(self) -> str:
        """
        Extracts raw metadata from the ONNX model file.
        Override of the base class method.
        """
        try:
            model = onnx.load(self.model_path)
            metadata = {}

            # Extract model metadata
            if model.metadata_props:
                for prop in model.metadata_props:
                    if hasattr(prop, 'key') and hasattr(prop, 'value'):
                        key = prop.key
                        value = prop.value
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='ignore')
                        metadata[key] = value

            # Extract basic model info
            metadata["model_ir_version"] = str(model.ir_version)
            metadata["producer_name"] = model.producer_name
            metadata["producer_version"] = model.producer_version
            metadata["domain"] = model.domain

            # Extract graph info if available
            if model.graph:
                metadata["graph_name"] = model.graph.name

                doc_string = model.graph.doc_string
                if isinstance(doc_string, bytes):
                    doc_string = doc_string.decode('utf-8', errors='ignore')
                metadata["doc_string"] = doc_string

                metadata["node_count"] = len(model.graph.node)
                metadata["input_count"] = len(model.graph.input)
                metadata["output_count"] = len(model.graph.output)

                # Extract operator types used in the model
                op_types = set()
                for node in model.graph.node:
                    if node.op_type:
                        op_types.add(node.op_type)

                metadata["operators_used"] = list(op_types)

                # Check for non-standard operators
                non_standard_ops = [op for op in op_types if op not in self.standard_onnx_operators]
                if non_standard_ops:
                    metadata["non_standard_operators"] = non_standard_ops

            return json.dumps(metadata, indent=2)

        except Exception as e:
            return f"Error extracting metadata: {str(e)}"