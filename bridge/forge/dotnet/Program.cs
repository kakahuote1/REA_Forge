using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using dnSpy.Contracts.Decompiler;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace REAForgeDnSpyWorker {

internal static class Program {
    static string workspace = string.Empty;

    static int Main(string[] args) {
        try {
            if (args.Length != 1) throw new InvalidOperationException("one_private_request_required");
            workspace = RequireWorkspace(Environment.GetEnvironmentVariable("REA_FORGE_DNSPY_WORKSPACE"));
            var requestPath = Path.GetFullPath(args[0]);
            if (!requestPath.StartsWith(workspace + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("request_outside_workspace");
            RejectReparsePath(requestPath);
            if (new FileInfo(requestPath).Length > 8 * 1024 * 1024)
                throw new InvalidOperationException("request_too_large");
            using var request = JsonDocument.Parse(File.ReadAllText(requestPath, Encoding.UTF8));
            var root = request.RootElement;
            var value = Execute(StringFrom(root, "operation"), root);
            var result = JsonSerializer.Serialize(new { ok = true, data = value });
            if (Encoding.UTF8.GetByteCount(result) > 7 * 1024 * 1024)
                throw new InvalidOperationException("response_budget_exceeded");
            Console.Out.WriteLine(result);
            return 0;
        } catch (Exception ex) {
            Console.Out.WriteLine(JsonSerializer.Serialize(new {
                ok = false, error = ex.GetType().Name + ":" + ex.Message.Substring(0, Math.Min(2048, ex.Message.Length))
            }));
            return 2;
        }
    }

    static string RequireWorkspace(string? value) {
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value) || value.StartsWith("\\\\", StringComparison.Ordinal))
            throw new InvalidOperationException("invalid_workspace");
        var full = Path.GetFullPath(value);
        if (!Directory.Exists(full) || (File.GetAttributes(full) & System.IO.FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("workspace_missing_or_reparse");
        return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    static object Execute(string operation, JsonElement request) => operation switch {
        "status" => new { pid = Environment.ProcessId, runtime = Environment.Version.ToString(), operations = new[] { "inspect", "inspect_metadata", "list_resources", "read_embedded_resource", "decompile_type", "decompile_type_as", "rename_type", "rename_method", "rename_field", "rename_property", "rename_event", "set_method_signature", "set_field_type", "set_property_type", "replace_custom_attributes", "replace_embedded_resource", "set_assembly_identity", "patch_instruction_to_nop", "replace_method_body", "compile_source" }, decompiler_languages = GetDecompilerLanguages() },
        "inspect" => Inspect(PathFrom(request, "path", true), request),
        "inspect_metadata" => InspectMetadata(PathFrom(request, "path", true)),
        "list_resources" => ListResources(PathFrom(request, "path", true)),
        "read_embedded_resource" => ReadEmbeddedResource(PathFrom(request, "path", true), ResourceNameFrom(request, "resource_name")),
        "decompile_type" => DecompileType(PathFrom(request, "path", true), UIntFrom(request, "type_token")),
        "decompile_type_as" => DecompileTypeAs(PathFrom(request, "path", true), UIntFrom(request, "type_token"), StringFrom(request, "language")),
        "rename_type" => RenameType(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), IdentifierFrom(request, "new_name")),
        "rename_method" => RenameMethod(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "method_token"), IdentifierFrom(request, "new_name")),
        "rename_field" => RenameField(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "field_token"), IdentifierFrom(request, "new_name")),
        "rename_property" => RenameProperty(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "property_token"), IdentifierFrom(request, "new_name")),
        "rename_event" => RenameEvent(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "event_token"), IdentifierFrom(request, "new_name")),
        "set_method_signature" => SetMethodSignature(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "method_token"), TypeSpecFrom(request, "return_type"), TypeSpecsFrom(request, "parameter_types")),
        "set_field_type" => SetFieldType(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "field_token"), TypeSpecFrom(request, "field_type")),
        "set_property_type" => SetPropertyType(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "property_token"), TypeSpecFrom(request, "property_type")),
        "replace_custom_attributes" => ReplaceCustomAttributes(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), StringFrom(request, "target_kind"), OptionalUIntFrom(request, "member_token"), CustomAttributeSpecsFrom(request, "attributes")),
        "replace_embedded_resource" => ReplaceEmbeddedResource(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), ResourceNameFrom(request, "resource_name"), Base64BytesFrom(request, "content_base64")),
        "set_assembly_identity" => SetAssemblyIdentity(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), IdentifierFrom(request, "assembly_name"), AssemblyVersionFrom(request, "assembly_version")),
        "patch_instruction_to_nop" => PatchInstructionToNop(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "method_token"), IntFrom(request, "instruction_index")),
        "replace_method_body" => ReplaceMethodBody(PathFrom(request, "path", true), PathFrom(request, "output_path", false, true), UIntFrom(request, "type_token"), UIntFrom(request, "method_token"), InstructionSpecsFrom(request, "instructions"), TypeSpecsOrEmptyFrom(request, "locals"), ExceptionHandlerSpecsOrEmptyFrom(request, "exception_handlers"), MaxStackFrom(request, "max_stack")),
        "compile_source" => CompileSource(PathFrom(request, "source_path", true), PathFrom(request, "output_path", false, true), OptionalStringFrom(request, "embedded_resource_name"), OptionalStringFrom(request, "embedded_resource_content_base64"), OptionalStringFrom(request, "output_kind") ?? "library"),
        _ => throw new InvalidOperationException("unsupported_operation"),
    };

    static string PathFrom(JsonElement request, string property, bool mustExist, bool mustBeNew = false) {
        var value = StringFrom(request, property);
        if (!Path.IsPathFullyQualified(value) || value.StartsWith("\\\\", StringComparison.Ordinal)) throw new InvalidOperationException("path_not_local");
        if (value.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.None).Any(part => part == "..")) throw new InvalidOperationException("path_parent_escape");
        var full = Path.GetFullPath(value); var prefix = workspace + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("path_outside_workspace");
        RejectReparsePath(full);
        if (mustExist && !File.Exists(full)) throw new InvalidOperationException("path_missing");
        if (mustExist && Directory.Exists(full)) throw new InvalidOperationException("path_not_file");
        if (mustBeNew && (File.Exists(full) || Directory.Exists(full))) throw new InvalidOperationException("output_already_exists");
        return full;
    }
    static string StringFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString())) throw new InvalidOperationException($"missing_{property}");
        return value.GetString()!;
    }
    static string? OptionalStringFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new InvalidOperationException($"invalid_{property}");
        return value.GetString();
    }
    static string IdentifierFrom(JsonElement request, string property) {
        var value = StringFrom(request, property);
        if (value.Length > 512 || value.IndexOfAny(new[] {'\\', '/', '\r', '\n', '\0'}) >= 0) throw new InvalidOperationException("invalid_identifier");
        return value;
    }
    static string ResourceNameFrom(JsonElement request, string property) {
        var value = StringFrom(request, property);
        if (value.Length > 512 || value.IndexOfAny(new[] {'\r', '\n', '\0'}) >= 0) throw new InvalidOperationException("invalid_resource_name");
        return value;
    }
    static JsonElement TypeSpecFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value)) throw new InvalidOperationException($"missing_{property}");
        ValidateTypeSpec(value, 0, false);
        return value;
    }
    static JsonElement[] TypeSpecsFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 64) throw new InvalidOperationException($"invalid_{property}");
        var values = new List<JsonElement>();
        foreach (var item in value.EnumerateArray()) {
            ValidateTypeSpec(item, 0, false);
            values.Add(item);
        }
        return values.ToArray();
    }
    static JsonElement[] TypeSpecsOrEmptyFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null) return Array.Empty<JsonElement>();
        return TypeSpecsFrom(request, property);
    }
    static JsonElement[] ExceptionHandlerSpecsOrEmptyFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null) return Array.Empty<JsonElement>();
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 16) throw new InvalidOperationException("invalid_exception_handler_list");
        var handlers = new List<JsonElement>();
        foreach (var handler in value.EnumerateArray()) { ValidateExceptionHandlerSpec(handler); handlers.Add(handler); }
        return handlers.ToArray();
    }
    static uint? OptionalUIntFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (!value.TryGetUInt32(out var result)) throw new InvalidOperationException($"invalid_{property}");
        return result;
    }
    static JsonElement[] CustomAttributeSpecsFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 16) throw new InvalidOperationException("invalid_custom_attribute_list");
        var values = new List<JsonElement>();
        foreach (var item in value.EnumerateArray()) {
            if (item.ValueKind != JsonValueKind.Object || item.EnumerateObject().Any(property => property.Name is not "constructor_token" and not "arguments") || !item.TryGetProperty("constructor_token", out var constructor) || !constructor.TryGetUInt32(out _)) throw new InvalidOperationException("invalid_custom_attribute_spec");
            if (item.TryGetProperty("arguments", out var arguments)) {
                if (arguments.ValueKind != JsonValueKind.Array || arguments.GetArrayLength() > 8) throw new InvalidOperationException("invalid_custom_attribute_arguments");
                foreach (var argument in arguments.EnumerateArray()) {
                    if (argument.ValueKind == JsonValueKind.String && argument.GetString()!.Length <= 4096 && argument.GetString()!.IndexOfAny(new[] {'\r', '\n', '\0'}) < 0) continue;
                    if (argument.ValueKind is JsonValueKind.True or JsonValueKind.False) continue;
                    if (argument.ValueKind == JsonValueKind.Number && argument.TryGetInt64(out _)) continue;
                    throw new InvalidOperationException("invalid_custom_attribute_argument");
                }
            }
            values.Add(item);
        }
        return values.ToArray();
    }
    static void ValidateExceptionHandlerSpec(JsonElement value) {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("kind", out var kindValue) || kindValue.ValueKind != JsonValueKind.String) throw new InvalidOperationException("invalid_exception_handler");
        var kind = kindValue.GetString();
        bool HasExactProperties(params string[] allowed) => value.EnumerateObject().All(property => allowed.Contains(property.Name, StringComparer.Ordinal));
        JsonElement Required(string name) => value.TryGetProperty(name, out var property) ? property : throw new InvalidOperationException($"missing_exception_handler_{name}");
        if (kind == "catch") {
            if (!HasExactProperties("kind", "try_start", "try_end", "handler_start", "handler_end", "catch_type")) throw new InvalidOperationException("invalid_exception_handler_properties");
            ValidateTypeSpec(Required("catch_type"), 0, true);
        } else if (kind == "finally") {
            if (!HasExactProperties("kind", "try_start", "try_end", "handler_start", "handler_end")) throw new InvalidOperationException("invalid_exception_handler_properties");
        } else throw new InvalidOperationException("unsupported_exception_handler_kind");
        foreach (var boundary in new[] { "try_start", "try_end", "handler_start", "handler_end" }) if (!Required(boundary).TryGetInt32(out _)) throw new InvalidOperationException("invalid_exception_handler_boundary");
    }
    static byte[] Base64BytesFrom(JsonElement request, string property) {
        var value = StringFrom(request, property);
        try {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length > 4 * 1024 * 1024) throw new InvalidOperationException("embedded_resource_too_large");
            return bytes;
        } catch (FormatException) { throw new InvalidOperationException($"invalid_{property}"); }
    }
    static Version AssemblyVersionFrom(JsonElement request, string property) {
        var value = StringFrom(request, property);
        if (value.Length > 32 || !Version.TryParse(value, out var version) || version.Build < 0 || version.Revision < 0) throw new InvalidOperationException("invalid_assembly_version");
        return version;
    }
    static void RejectReparsePath(string full) {
        var relative = Path.GetRelativePath(workspace, full);
        if (relative == "." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || relative.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal)) throw new InvalidOperationException("path_outside_workspace");
        var current = workspace;
        foreach (var part in relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries)) {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & System.IO.FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("path_reparse_point");
        }
    }
    static uint UIntFrom(JsonElement request, string property) { if (!request.TryGetProperty(property, out var value) || !value.TryGetUInt32(out var result)) throw new InvalidOperationException($"missing_{property}"); return result; }
    static int IntFrom(JsonElement request, string property) { if (!request.TryGetProperty(property, out var value) || !value.TryGetInt32(out var result)) throw new InvalidOperationException($"missing_{property}"); return result; }
    static ushort MaxStackFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || !value.TryGetInt32(out var result) || result < 1 || result > 64) throw new InvalidOperationException("invalid_max_stack");
        return (ushort)result;
    }
    static JsonElement[] InstructionSpecsFrom(JsonElement request, string property) {
        if (!request.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is < 1 or > 512) throw new InvalidOperationException("invalid_instruction_list");
        var values = new List<JsonElement>();
        foreach (var item in value.EnumerateArray()) { ValidateInstructionSpec(item); values.Add(item); }
        var finalOpcode = values[^1].GetProperty("opcode").GetString();
        if (finalOpcode is not "ret" and not "throw") throw new InvalidOperationException("method_body_must_terminate");
        foreach (var specification in values.Where(IsBranchSpec)) {
            if (specification.GetProperty("target").GetInt32() < 0 || specification.GetProperty("target").GetInt32() >= values.Count) throw new InvalidOperationException("branch_target_index_invalid");
        }
        return values.ToArray();
    }
    static void ValidateInstructionSpec(JsonElement value) {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("opcode", out var opcodeValue) || opcodeValue.ValueKind != JsonValueKind.String) throw new InvalidOperationException("invalid_instruction_spec");
        var opcode = opcodeValue.GetString();
        if (opcode == "endfinally") {
            if (value.EnumerateObject().Any(property => property.Name != "opcode")) throw new InvalidOperationException("invalid_instruction_properties");
            return;
        }
        bool HasExactProperties(params string[] allowed) => value.EnumerateObject().All(property => allowed.Contains(property.Name, StringComparer.Ordinal));
        JsonElement Required(string name) => value.TryGetProperty(name, out var property) ? property : throw new InvalidOperationException($"missing_instruction_{name}");
        if (opcode is "nop" or "ret" or "throw" or "ldnull" or "dup" or "pop" or "add" or "sub" or "mul" or "div" or "rem" or "neg" or "and" or "or" or "xor" or "not" or "ceq" or "cgt" or "clt" or "conv.i4" or "conv.i8" or "ldarg.0" or "ldarg.1" or "ldarg.2" or "ldarg.3") {
            if (!HasExactProperties("opcode")) throw new InvalidOperationException("invalid_instruction_properties");
            return;
        }
        if (opcode == "ldc.i4") {
            if (!HasExactProperties("opcode", "value") || !Required("value").TryGetInt32(out _)) throw new InvalidOperationException("invalid_instruction_integer");
            return;
        }
        if (opcode == "ldc.i8") {
            if (!HasExactProperties("opcode", "value") || !Required("value").TryGetInt64(out _)) throw new InvalidOperationException("invalid_instruction_integer");
            return;
        }
        if (opcode == "ldstr") {
            var text = Required("value");
            if (!HasExactProperties("opcode", "value") || text.ValueKind != JsonValueKind.String || text.GetString()!.Length > 4096 || text.GetString()!.IndexOfAny(new[] {'\r', '\n', '\0'}) >= 0) throw new InvalidOperationException("invalid_instruction_string");
            return;
        }
        if (opcode is "call" or "callvirt" or "newobj") {
            if (!HasExactProperties("opcode", "method_token") || !Required("method_token").TryGetUInt32(out _)) throw new InvalidOperationException("invalid_instruction_method");
            return;
        }
        if (opcode is "ldfld" or "ldsfld" or "stfld" or "stsfld") {
            if (!HasExactProperties("opcode", "field_token") || !Required("field_token").TryGetUInt32(out _)) throw new InvalidOperationException("invalid_instruction_field");
            return;
        }
        if (opcode is "box" or "unbox.any" or "castclass" or "isinst" or "newarr") {
            if (!HasExactProperties("opcode", "type")) throw new InvalidOperationException("invalid_instruction_properties");
            ValidateTypeSpec(Required("type"), 0, true);
            return;
        }
        if (opcode is "br" or "brtrue" or "brfalse" or "beq" or "bne.un" or "bgt" or "bge" or "blt" or "ble" or "leave") {
            if (!HasExactProperties("opcode", "target") || !Required("target").TryGetInt32(out _)) throw new InvalidOperationException("invalid_instruction_branch");
            return;
        }
        if (opcode is "ldloc" or "stloc" or "ldloca") {
            if (!HasExactProperties("opcode", "local_index") || !Required("local_index").TryGetInt32(out var localIndex) || localIndex < 0 || localIndex >= 64) throw new InvalidOperationException("invalid_instruction_local");
            return;
        }
        throw new InvalidOperationException("unsupported_instruction_opcode");
    }
    static bool IsBranchSpec(JsonElement specification) => specification.GetProperty("opcode").GetString() is "br" or "brtrue" or "brfalse" or "beq" or "bne.un" or "bgt" or "bge" or "blt" or "ble" or "leave";

    static int? InstructionIndex(CilBody body, Instruction instruction) => instruction is null ? null : body.Instructions.IndexOf(instruction);
    static object[] ExceptionHandlerFacts(CilBody body) => body.ExceptionHandlers.Select(handler => (object)new {
        kind = handler.HandlerType.ToString(),
        try_start_index = InstructionIndex(body, handler.TryStart),
        try_end_index = InstructionIndex(body, handler.TryEnd),
        handler_start_index = InstructionIndex(body, handler.HandlerStart),
        handler_end_index = InstructionIndex(body, handler.HandlerEnd),
        catch_type = handler.CatchType?.FullName
    }).ToArray();
    static object? CustomAttributeArgumentFact(object? value) => value switch { UTF8String text => text.String, string text => text, bool flag => flag, sbyte number => number, byte number => number, short number => number, ushort number => number, int number => number, uint number => number, long number => number, ulong number => number, _ => null };
    static object[] CustomAttributeFacts(IEnumerable<CustomAttribute> attributes) => attributes.Select(attribute => (object)new { type = attribute.AttributeType.FullName, arguments = attribute.ConstructorArguments.Select(argument => new { type = argument.Type.FullName, value = CustomAttributeArgumentFact(argument.Value) }).ToArray() }).ToArray();
    static object? OperandFact(object? operand) => operand switch {
        null => null,
        string text => text.Length <= 4096 ? text : text.Substring(0, 4096),
        int value => value, long value => value, sbyte value => value,
        byte value => value, float value => float.IsFinite(value) ? (object)value : value.ToString(),
        double value => double.IsFinite(value) ? (object)value : value.ToString(),
        IMDTokenProvider metadata => new { token = metadata.MDToken.Raw, display = metadata.ToString() },
        _ => null
    };
    static object MethodFacts(MethodDef method) => new {
        name = method.Name.String,
        token = method.MDToken.Raw,
        return_type = method.MethodSig?.RetType.FullName,
        parameter_types = method.MethodSig?.Params.Select(parameter => parameter.FullName).ToArray() ?? Array.Empty<string>(),
        has_body = method.HasBody,
        custom_attributes = CustomAttributeFacts(method.CustomAttributes),
        local_types = method.HasBody ? method.Body.Variables.Select(local => local.Type.FullName).ToArray() : Array.Empty<string>(),
        instructions = method.HasBody ? method.Body.Instructions.Select(instruction => instruction.OpCode.Name).ToArray() : Array.Empty<string>(),
        instruction_details = method.HasBody ? method.Body.Instructions.Select((instruction, index) => new { index, opcode = instruction.OpCode.Name, operand = OperandFact(instruction.Operand), branch_target_index = instruction.Operand is Instruction target ? (int?)method.Body.Instructions.IndexOf(target) : null }).ToArray() : Array.Empty<object>(),
        exception_handlers = method.HasBody ? ExceptionHandlerFacts(method.Body) : Array.Empty<object>()
    };
    static object TypeFacts(TypeDef type) => new {
        name = type.FullName,
        token = type.MDToken.Raw,
        custom_attributes = CustomAttributeFacts(type.CustomAttributes),
        fields = type.Fields.Select(field => new { name = field.Name.String, token = field.MDToken.Raw, type = field.FieldSig?.Type.FullName, custom_attributes = CustomAttributeFacts(field.CustomAttributes) }).ToArray(),
        properties = type.Properties.Select(property => new { name = property.Name.String, token = property.MDToken.Raw, type = property.PropertySig?.RetType.FullName, custom_attributes = CustomAttributeFacts(property.CustomAttributes) }).ToArray(),
        events = type.Events.Select(@event => new { name = @event.Name.String, token = @event.MDToken.Raw, type = @event.EventType?.FullName, custom_attributes = CustomAttributeFacts(@event.CustomAttributes) }).ToArray(),
        methods = type.Methods.Select(MethodFacts).ToArray()
    };
    static object Inspect(string path, JsonElement request) {
        var offset = request.TryGetProperty("offset", out var offsetValue) ? offsetValue.GetInt32() : 0;
        var limit = request.TryGetProperty("limit", out var limitValue) ? limitValue.GetInt32() : 16;
        var details = !request.TryGetProperty("details", out var detailsValue) || detailsValue.GetBoolean();
        if (offset < 0 || limit < 1 || limit > 64) throw new InvalidOperationException("invalid_inspect_page");
        using var module = ModuleDefMD.Load(path);
        var all = module.GetTypes().Where(type => !type.IsGlobalModuleType).ToArray();
        var page = new List<object>();
        var bytes = 0;
        foreach (var type in all.Skip(offset).Take(limit)) {
            object fact = details ? TypeFacts(type) : new { name = type.FullName, token = type.MDToken.Raw, summary_only = true, detail_reason = "requested_summary", method_count = type.Methods.Count, field_count = type.Fields.Count };
            var size = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(fact));
            if (size > 700_000) {
                fact = new { name = type.FullName, token = type.MDToken.Raw, summary_only = true, detail_reason = "type_facts_exceed_response_budget", method_count = type.Methods.Count, field_count = type.Fields.Count };
                size = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(fact));
            }
            if (page.Count > 0 && bytes + size > 750_000) break;
            page.Add(fact);
            bytes += size;
        }
        var next = Math.Min(all.Length, offset + page.Count);
        return new { assembly = module.Assembly?.FullName, module = module.Name.String, types = page.ToArray(), total_types = all.Length, offset, next_offset = next < all.Length ? (int?)next : null, truncated = next < all.Length };
    }
    static object InspectMetadata(string path) {
        using var module = ModuleDefMD.Load(path);
        return new {
            assembly = module.Assembly?.FullName,
            module = module.Name.String,
            mvid = module.Mvid.ToString(),
            runtime_version = module.RuntimeVersion,
            machine = module.Machine.ToString(),
            characteristics = module.Characteristics.ToString(),
            assembly_references = module.GetAssemblyRefs().Select(reference => reference.FullName).OrderBy(name => name, StringComparer.Ordinal).ToArray(),
            module_references = module.GetModuleRefs().Select(reference => reference.Name.String).OrderBy(name => name, StringComparer.Ordinal).ToArray(),
            type_references = module.GetTypeRefs().Select(reference => reference.FullName).Distinct(StringComparer.Ordinal).OrderBy(name => name, StringComparer.Ordinal).Take(512).ToArray(),
            resources = ResourceSummaries(module).ToArray(),
            type_count = module.GetTypes().Count(type => !type.IsGlobalModuleType)
        };
    }
    static object ListResources(string path) {
        using var module = ModuleDefMD.Load(path);
        return new { resources = ResourceSummaries(module).ToArray() };
    }
    static object ReadEmbeddedResource(string path, string resourceName) {
        using var module = ModuleDefMD.Load(path);
        var resource = module.Resources.OfType<EmbeddedResource>().FirstOrDefault(candidate => string.Equals(candidate.Name.String, resourceName, StringComparison.Ordinal));
        if (resource is null) throw new InvalidOperationException("embedded_resource_not_found");
        var data = resource.CreateReader().ToArray();
        if (data.Length > 4 * 1024 * 1024) throw new InvalidOperationException("embedded_resource_too_large");
        return new { name = resource.Name.String, size = data.Length, sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant(), content_base64 = Convert.ToBase64String(data) };
    }
    static IEnumerable<object> ResourceSummaries(ModuleDefMD module) {
        foreach (var resource in module.Resources.OrderBy(item => item.Name.String, StringComparer.Ordinal)) {
            var embedded = resource as EmbeddedResource;
            var size = embedded is null ? (uint?)null : embedded.Length;
            yield return new { name = resource.Name.String, kind = resource.ResourceType.ToString(), attributes = resource.Attributes.ToString(), size };
        }
    }
    static object DecompileType(string path, uint typeToken) {
        return DecompileTypeAs(path, typeToken, "C#");
    }
    static object DecompileTypeAs(string path, uint typeToken, string languageName) {
        using var module = ModuleDefMD.Load(path);
        var type = FindType(module, typeToken); var language = GetDecompiler(languageName);
        using var text = new StringWriter(); using var output = new TextWriterDecompilerOutput(text);
        language.Decompile(type, output, new DecompilationContext());
        return new { type = type.FullName, language = language.GenericNameUI, source = text.ToString() };
    }
    static object RenameType(string path, string output, uint typeToken, string newName) {
        using var module = ModuleDefMD.Load(path); var type = FindType(module, typeToken); var before = type.Name.String; type.Name = newName; module.Write(output);
        return new { changed = "type", before, after = newName, output_path = output };
    }
    static object RenameMethod(string path, string output, uint typeToken, uint methodToken, string newName) {
        using var module = ModuleDefMD.Load(path); var method = FindMethod(FindType(module, typeToken), methodToken); var before = method.Name.String; method.Name = newName; module.Write(output);
        return new { changed = "method", before, after = newName, output_path = output };
    }
    static object RenameField(string path, string output, uint typeToken, uint fieldToken, string newName) {
        using var module = ModuleDefMD.Load(path); var field = FindField(FindType(module, typeToken), fieldToken); var before = field.Name.String; field.Name = newName; module.Write(output);
        return new { changed = "field", before, after = newName, output_path = output };
    }
    static object RenameProperty(string path, string output, uint typeToken, uint propertyToken, string newName) {
        using var module = ModuleDefMD.Load(path); var property = FindProperty(FindType(module, typeToken), propertyToken); var before = property.Name.String; property.Name = newName; module.Write(output);
        return new { changed = "property", before, after = newName, output_path = output };
    }
    static object RenameEvent(string path, string output, uint typeToken, uint eventToken, string newName) {
        using var module = ModuleDefMD.Load(path); var @event = FindEvent(FindType(module, typeToken), eventToken); var before = @event.Name.String; @event.Name = newName; module.Write(output);
        return new { changed = "event", before, after = newName, output_path = output };
    }
    static object SetMethodSignature(string path, string output, uint typeToken, uint methodToken, JsonElement returnTypeSpec, JsonElement[] parameterTypeSpecs) {
        using var module = ModuleDefMD.Load(path); var method = FindMethod(FindType(module, typeToken), methodToken);
        if (method.MethodSig is null) throw new InvalidOperationException("method_signature_missing");
        var before = new { return_type = method.MethodSig.RetType.FullName, parameter_types = method.MethodSig.Params.Select(parameter => parameter.FullName).ToArray() };
        method.MethodSig.RetType = ResolveTypeSpec(module, returnTypeSpec);
        method.MethodSig.Params.Clear();
        foreach (var parameter in parameterTypeSpecs) method.MethodSig.Params.Add(ResolveTypeSpec(module, parameter));
        var parameterDefinitions = method.ParamDefs.Where(parameter => parameter.Sequence != 0).OrderBy(parameter => parameter.Sequence).ToList();
        foreach (var extra in parameterDefinitions.Skip(parameterTypeSpecs.Length).ToArray()) method.ParamDefs.Remove(extra);
        for (var index = 0; index < parameterTypeSpecs.Length; index++) {
            if (index < parameterDefinitions.Count) parameterDefinitions[index].Sequence = (ushort)(index + 1);
            else method.ParamDefs.Add(new ParamDefUser($"arg{index}", (ushort)(index + 1)));
        }
        method.Parameters.UpdateParameterTypes();
        if (method.HasBody) method.Body.KeepOldMaxStack = true;
        var options = new ModuleWriterOptions(module);
        options.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
        module.Write(output, options);
        return new { changed = "method_signature", before, after = new { return_type = method.MethodSig.RetType.FullName, parameter_types = method.MethodSig.Params.Select(parameter => parameter.FullName).ToArray() }, output_path = output };
    }
    static object SetFieldType(string path, string output, uint typeToken, uint fieldToken, JsonElement typeSpec) {
        using var module = ModuleDefMD.Load(path); var field = FindField(FindType(module, typeToken), fieldToken); var before = field.FieldSig?.Type.FullName;
        field.FieldSig = new FieldSig(ResolveTypeSpec(module, typeSpec)); module.Write(output);
        return new { changed = "field_type", before, after = field.FieldSig.Type.FullName, output_path = output };
    }
    static object SetPropertyType(string path, string output, uint typeToken, uint propertyToken, JsonElement typeSpec) {
        using var module = ModuleDefMD.Load(path); var property = FindProperty(FindType(module, typeToken), propertyToken);
        if (property.PropertySig is null) throw new InvalidOperationException("property_signature_missing");
        var before = property.PropertySig.RetType.FullName; property.PropertySig.RetType = ResolveTypeSpec(module, typeSpec); module.Write(output);
        return new { changed = "property_type", before, after = property.PropertySig.RetType.FullName, output_path = output };
    }
    static IHasCustomAttribute FindCustomAttributeTarget(TypeDef type, string targetKind, uint? memberToken) {
        if (targetKind == "type") {
            if (memberToken is not null) throw new InvalidOperationException("custom_attribute_member_token_for_type");
            return type;
        }
        if (memberToken is null) throw new InvalidOperationException("custom_attribute_member_token_missing");
        return targetKind switch {
            "method" => FindMethod(type, memberToken.Value),
            "field" => FindField(type, memberToken.Value),
            "property" => FindProperty(type, memberToken.Value),
            "event" => FindEvent(type, memberToken.Value),
            _ => throw new InvalidOperationException("custom_attribute_target_kind_invalid")
        };
    }
    static object CustomAttributeArgumentValue(TypeSig type, JsonElement value) => type.ElementType switch {
        ElementType.String when value.ValueKind == JsonValueKind.String => value.GetString()!,
        ElementType.Boolean when value.ValueKind is JsonValueKind.True or JsonValueKind.False => value.GetBoolean(),
        ElementType.I4 when value.TryGetInt32(out var number) => number,
        ElementType.I8 when value.TryGetInt64(out var longNumber) => longNumber,
        _ => throw new InvalidOperationException("custom_attribute_argument_type_invalid")
    };
    static object ReplaceCustomAttributes(string path, string output, uint typeToken, string targetKind, uint? memberToken, JsonElement[] specifications) {
        using var module = ModuleDefMD.Load(path);
        var target = FindCustomAttributeTarget(FindType(module, typeToken), targetKind, memberToken);
        var before = CustomAttributeFacts(target.CustomAttributes);
        var replacements = new List<CustomAttribute>();
        foreach (var specification in specifications) {
            var constructor = module.ResolveToken(specification.GetProperty("constructor_token").GetUInt32()) as ICustomAttributeType;
            if (constructor is not IMethod method || method.MethodSig is null) throw new InvalidOperationException("custom_attribute_constructor_invalid");
            var arguments = specification.TryGetProperty("arguments", out var argumentValues) ? argumentValues.EnumerateArray().ToArray() : Array.Empty<JsonElement>();
            if (method.MethodSig.Params.Count != arguments.Length) throw new InvalidOperationException("custom_attribute_argument_count_invalid");
            var replacement = new CustomAttribute(constructor);
            for (var index = 0; index < arguments.Length; index++) replacement.ConstructorArguments.Add(new CAArgument(method.MethodSig.Params[index], CustomAttributeArgumentValue(method.MethodSig.Params[index], arguments[index])));
            replacements.Add(replacement);
        }
        target.CustomAttributes.Clear();
        foreach (var replacement in replacements) target.CustomAttributes.Add(replacement);
        module.Write(output);
        return new { changed = "custom_attributes", target_kind = targetKind, before, after = CustomAttributeFacts(target.CustomAttributes), output_path = output };
    }
    static object ReplaceEmbeddedResource(string path, string output, string resourceName, byte[] content) {
        using var module = ModuleDefMD.Load(path); var resource = module.Resources.OfType<EmbeddedResource>().FirstOrDefault(candidate => string.Equals(candidate.Name.String, resourceName, StringComparison.Ordinal));
        if (resource is null) throw new InvalidOperationException("embedded_resource_not_found");
        var before = resource.CreateReader().ToArray(); var index = module.Resources.IndexOf(resource);
        module.Resources[index] = new EmbeddedResource(resource.Name, content, resource.Attributes); module.Write(output);
        return new { changed = "embedded_resource", name = resourceName, before_sha256 = Convert.ToHexString(SHA256.HashData(before)).ToLowerInvariant(), after_sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(), size = content.Length, output_path = output };
    }
    static object SetAssemblyIdentity(string path, string output, string assemblyName, Version assemblyVersion) {
        using var module = ModuleDefMD.Load(path); var assembly = module.Assembly ?? throw new InvalidOperationException("assembly_missing"); var before = assembly.FullName;
        assembly.Name = assemblyName; assembly.Version = assemblyVersion; module.Write(output);
        return new { changed = "assembly_identity", before, after = assembly.FullName, output_path = output };
    }
    static object PatchInstructionToNop(string path, string output, uint typeToken, uint methodToken, int instructionIndex) {
        using var module = ModuleDefMD.Load(path); var method = FindMethod(FindType(module, typeToken), methodToken);
        if (!method.HasBody || instructionIndex < 0 || instructionIndex >= method.Body.Instructions.Count) throw new InvalidOperationException("instruction_index_invalid");
        var instruction = method.Body.Instructions[instructionIndex]; var before = instruction.OpCode.Name; instruction.OpCode = OpCodes.Nop; instruction.Operand = null; method.Body.KeepOldMaxStack = true; module.Write(output);
        return new { changed = "instruction", before, after = "nop", instruction_index = instructionIndex, output_path = output };
    }
    static object ReplaceMethodBody(string path, string output, uint typeToken, uint methodToken, JsonElement[] instructionSpecs, JsonElement[] localSpecs, JsonElement[] exceptionHandlerSpecs, ushort maxStack) {
        using var module = ModuleDefMD.Load(path); var method = FindMethod(FindType(module, typeToken), methodToken);
        var before = method.HasBody ? method.Body.Instructions.Select(instruction => instruction.OpCode.Name).ToArray() : Array.Empty<string>();
        var body = new CilBody { KeepOldMaxStack = true, MaxStack = maxStack, InitLocals = localSpecs.Length > 0 };
        foreach (var local in localSpecs) body.Variables.Add(new Local(ResolveTypeSpec(module, local)));
        foreach (var specification in instructionSpecs) {
            if (specification.GetProperty("opcode").GetString() is "ldloc" or "stloc" or "ldloca" && specification.GetProperty("local_index").GetInt32() >= body.Variables.Count) throw new InvalidOperationException("local_index_invalid");
            body.Instructions.Add(CreateInstruction(module, body, specification));
        }
        for (var index = 0; index < instructionSpecs.Length; index++) {
            if (!IsBranchSpec(instructionSpecs[index])) continue;
            body.Instructions[index].OpCode = BranchOpcode(instructionSpecs[index].GetProperty("opcode").GetString()!);
            body.Instructions[index].Operand = body.Instructions[instructionSpecs[index].GetProperty("target").GetInt32()];
        }
        foreach (var specification in exceptionHandlerSpecs) body.ExceptionHandlers.Add(CreateExceptionHandler(module, body, specification));
        method.Body = body;
        var options = new ModuleWriterOptions(module); options.MetadataOptions.Flags |= MetadataFlags.KeepOldMaxStack;
        module.Write(output, options);
        return new { changed = "method_body", before, after = body.Instructions.Select(instruction => instruction.OpCode.Name).ToArray(), local_types = body.Variables.Select(local => local.Type.FullName).ToArray(), exception_handler_count = body.ExceptionHandlers.Count, max_stack = maxStack, output_path = output };
    }
    static ExceptionHandler CreateExceptionHandler(ModuleDefMD module, CilBody body, JsonElement specification) {
        int Boundary(string name) { var index = specification.GetProperty(name).GetInt32(); if (index < 0 || index >= body.Instructions.Count) throw new InvalidOperationException("exception_handler_boundary_invalid"); return index; }
        var tryStart = Boundary("try_start"); var tryEnd = Boundary("try_end"); var handlerStart = Boundary("handler_start"); var handlerEnd = Boundary("handler_end");
        if (tryStart >= tryEnd || handlerStart >= handlerEnd) throw new InvalidOperationException("exception_handler_range_invalid");
        var kind = specification.GetProperty("kind").GetString();
        var handler = new ExceptionHandler(kind == "catch" ? ExceptionHandlerType.Catch : ExceptionHandlerType.Finally) { TryStart = body.Instructions[tryStart], TryEnd = body.Instructions[tryEnd], HandlerStart = body.Instructions[handlerStart], HandlerEnd = body.Instructions[handlerEnd] };
        if (kind == "catch") handler.CatchType = ResolveExistingTypeReference(module, specification.GetProperty("catch_type"));
        return handler;
    }
    static Instruction CreateInstruction(ModuleDefMD module, CilBody body, JsonElement specification) {
        var opcode = specification.GetProperty("opcode").GetString()!;
        return opcode switch {
            "nop" => Instruction.Create(OpCodes.Nop), "ret" => Instruction.Create(OpCodes.Ret), "throw" => Instruction.Create(OpCodes.Throw), "ldnull" => Instruction.Create(OpCodes.Ldnull), "dup" => Instruction.Create(OpCodes.Dup), "pop" => Instruction.Create(OpCodes.Pop), "add" => Instruction.Create(OpCodes.Add), "sub" => Instruction.Create(OpCodes.Sub), "mul" => Instruction.Create(OpCodes.Mul), "div" => Instruction.Create(OpCodes.Div), "rem" => Instruction.Create(OpCodes.Rem), "neg" => Instruction.Create(OpCodes.Neg), "and" => Instruction.Create(OpCodes.And), "or" => Instruction.Create(OpCodes.Or), "xor" => Instruction.Create(OpCodes.Xor), "not" => Instruction.Create(OpCodes.Not), "ceq" => Instruction.Create(OpCodes.Ceq), "cgt" => Instruction.Create(OpCodes.Cgt), "clt" => Instruction.Create(OpCodes.Clt), "conv.i4" => Instruction.Create(OpCodes.Conv_I4), "conv.i8" => Instruction.Create(OpCodes.Conv_I8), "ldarg.0" => Instruction.Create(OpCodes.Ldarg_0), "ldarg.1" => Instruction.Create(OpCodes.Ldarg_1), "ldarg.2" => Instruction.Create(OpCodes.Ldarg_2), "ldarg.3" => Instruction.Create(OpCodes.Ldarg_3),
            "ldc.i4" => Instruction.Create(OpCodes.Ldc_I4, specification.GetProperty("value").GetInt32()),
            "endfinally" => Instruction.Create(OpCodes.Endfinally),
            "ldc.i8" => Instruction.Create(OpCodes.Ldc_I8, specification.GetProperty("value").GetInt64()),
            "ldstr" => Instruction.Create(OpCodes.Ldstr, specification.GetProperty("value").GetString()!),
            "call" => Instruction.Create(OpCodes.Call, ResolveMethodOperand(module, specification.GetProperty("method_token").GetUInt32())),
            "callvirt" => Instruction.Create(OpCodes.Callvirt, ResolveMethodOperand(module, specification.GetProperty("method_token").GetUInt32())),
            "newobj" => Instruction.Create(OpCodes.Newobj, ResolveMethodOperand(module, specification.GetProperty("method_token").GetUInt32())),
            "ldfld" => Instruction.Create(OpCodes.Ldfld, ResolveFieldOperand(module, specification.GetProperty("field_token").GetUInt32())),
            "ldsfld" => Instruction.Create(OpCodes.Ldsfld, ResolveFieldOperand(module, specification.GetProperty("field_token").GetUInt32())),
            "stfld" => Instruction.Create(OpCodes.Stfld, ResolveFieldOperand(module, specification.GetProperty("field_token").GetUInt32())),
            "stsfld" => Instruction.Create(OpCodes.Stsfld, ResolveFieldOperand(module, specification.GetProperty("field_token").GetUInt32())),
            "box" => Instruction.Create(OpCodes.Box, ResolveExistingTypeReference(module, specification.GetProperty("type"))),
            "unbox.any" => Instruction.Create(OpCodes.Unbox_Any, ResolveExistingTypeReference(module, specification.GetProperty("type"))),
            "castclass" => Instruction.Create(OpCodes.Castclass, ResolveExistingTypeReference(module, specification.GetProperty("type"))),
            "isinst" => Instruction.Create(OpCodes.Isinst, ResolveExistingTypeReference(module, specification.GetProperty("type"))),
            "newarr" => Instruction.Create(OpCodes.Newarr, ResolveExistingTypeReference(module, specification.GetProperty("type"))),
            "ldloc" => Instruction.Create(OpCodes.Ldloc, body.Variables[specification.GetProperty("local_index").GetInt32()]),
            "stloc" => Instruction.Create(OpCodes.Stloc, body.Variables[specification.GetProperty("local_index").GetInt32()]),
            "ldloca" => Instruction.Create(OpCodes.Ldloca, body.Variables[specification.GetProperty("local_index").GetInt32()]),
            "br" or "brtrue" or "brfalse" or "beq" or "bne.un" or "bgt" or "bge" or "blt" or "ble" or "leave" => Instruction.Create(OpCodes.Nop),
            _ => throw new InvalidOperationException("unsupported_instruction_opcode")
        };
    }
    static OpCode BranchOpcode(string opcode) => opcode switch {
        "br" => OpCodes.Br, "brtrue" => OpCodes.Brtrue, "brfalse" => OpCodes.Brfalse, "beq" => OpCodes.Beq, "bne.un" => OpCodes.Bne_Un, "bgt" => OpCodes.Bgt, "bge" => OpCodes.Bge, "blt" => OpCodes.Blt, "ble" => OpCodes.Ble, "leave" => OpCodes.Leave, _ => throw new InvalidOperationException("unsupported_instruction_opcode")
    };
    static IMethod ResolveMethodOperand(ModuleDefMD module, uint token) => module.ResolveToken(token) as IMethod ?? throw new InvalidOperationException("instruction_method_token_invalid");
    static IField ResolveFieldOperand(ModuleDefMD module, uint token) => module.ResolveToken(token) as IField ?? throw new InvalidOperationException("instruction_field_token_invalid");
    static object CompileSource(string sourcePath, string output, string? embeddedResourceName, string? embeddedResourceContentBase64, string outputKind) {
        var trusted = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string;
        if (string.IsNullOrWhiteSpace(trusted)) throw new InvalidOperationException("trusted_platform_assemblies_missing");
        if ((embeddedResourceName is null) != (embeddedResourceContentBase64 is null)) throw new InvalidOperationException("embedded_resource_pair_required");
        var refs = trusted.Split(Path.PathSeparator).Select(path => MetadataReference.CreateFromFile(path));
        var kind = outputKind switch { "library" => OutputKind.DynamicallyLinkedLibrary, "console" => OutputKind.ConsoleApplication, _ => throw new InvalidOperationException("invalid_output_kind") };
        var compilation = CSharpCompilation.Create(Path.GetFileNameWithoutExtension(output), new[] { CSharpSyntaxTree.ParseText(File.ReadAllText(sourcePath, Encoding.UTF8)) }, refs, new CSharpCompilationOptions(kind));
        IEnumerable<ResourceDescription>? resources = null;
        string? resourceName = null;
        if (embeddedResourceName is not null) {
            if (embeddedResourceName.Length == 0 || embeddedResourceName.Length > 512 || embeddedResourceName.IndexOfAny(new[] {'\r', '\n', '\0'}) >= 0) throw new InvalidOperationException("invalid_embedded_resource_name");
            byte[] resourceData;
            try { resourceData = Convert.FromBase64String(embeddedResourceContentBase64!); } catch (FormatException) { throw new InvalidOperationException("invalid_embedded_resource_content"); }
            if (resourceData.Length > 4 * 1024 * 1024) throw new InvalidOperationException("embedded_resource_too_large");
            resourceName = embeddedResourceName;
            resources = new[] { new ResourceDescription(resourceName, () => new MemoryStream(resourceData, writable: false), true) };
        }
        var result = compilation.Emit(output, manifestResources: resources);
        return new { compiled = result.Success, output_path = output, embedded_resource_name = resourceName, diagnostics = result.Diagnostics.Select(d => d.ToString()).ToArray() };
    }
    static TypeDef FindType(ModuleDefMD module, uint token) => module.ResolveToken(token) as TypeDef ?? throw new InvalidOperationException("type_token_invalid");
    static MethodDef FindMethod(TypeDef type, uint token) => type.Methods.FirstOrDefault(m => m.MDToken.Raw == token) ?? throw new InvalidOperationException("method_token_invalid");
    static FieldDef FindField(TypeDef type, uint token) => type.Fields.FirstOrDefault(field => field.MDToken.Raw == token) ?? throw new InvalidOperationException("field_token_invalid");
    static PropertyDef FindProperty(TypeDef type, uint token) => type.Properties.FirstOrDefault(property => property.MDToken.Raw == token) ?? throw new InvalidOperationException("property_token_invalid");
    static EventDef FindEvent(TypeDef type, uint token) => type.Events.FirstOrDefault(@event => @event.MDToken.Raw == token) ?? throw new InvalidOperationException("event_token_invalid");
    static bool IsPrimitiveTypeName(string name) => name is "void" or "bool" or "char" or "int8" or "uint8" or "int16" or "uint16" or "int32" or "uint32" or "int64" or "uint64" or "float32" or "float64" or "string" or "object" or "nativeint" or "nativeuint";
    static TypeSig PrimitiveType(ModuleDefMD module, string name) => name switch {
        "void" => module.CorLibTypes.Void, "bool" => module.CorLibTypes.Boolean, "char" => module.CorLibTypes.Char, "int8" => module.CorLibTypes.SByte, "uint8" => module.CorLibTypes.Byte, "int16" => module.CorLibTypes.Int16, "uint16" => module.CorLibTypes.UInt16, "int32" => module.CorLibTypes.Int32, "uint32" => module.CorLibTypes.UInt32, "int64" => module.CorLibTypes.Int64, "uint64" => module.CorLibTypes.UInt64, "float32" => module.CorLibTypes.Single, "float64" => module.CorLibTypes.Double, "string" => module.CorLibTypes.String, "object" => module.CorLibTypes.Object, "nativeint" => module.CorLibTypes.IntPtr, "nativeuint" => module.CorLibTypes.UIntPtr, _ => throw new InvalidOperationException("unsupported_primitive_type")
    };
    static void ValidateTypeSpec(JsonElement value, int depth, bool requireExistingType) {
        if (depth > 8) throw new InvalidOperationException("type_spec_too_deep");
        if (value.ValueKind == JsonValueKind.String) {
            if (requireExistingType || value.GetString() is not string name || !IsPrimitiveTypeName(name)) throw new InvalidOperationException("unsupported_type_spec");
            return;
        }
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("kind", out var kindValue) || kindValue.ValueKind != JsonValueKind.String) throw new InvalidOperationException("invalid_type_spec");
        var kind = kindValue.GetString();
        bool HasExactProperties(params string[] allowed) => value.EnumerateObject().All(property => allowed.Contains(property.Name, StringComparer.Ordinal));
        JsonElement Required(string name) => value.TryGetProperty(name, out var property) ? property : throw new InvalidOperationException($"missing_type_spec_{name}");
        switch (kind) {
            case "existing_type":
                if (!HasExactProperties("kind", "full_name", "is_value_type")) throw new InvalidOperationException("invalid_type_spec_properties");
                var fullName = Required("full_name");
                if (fullName.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(fullName.GetString()) || fullName.GetString()!.Length > 1024 || fullName.GetString()!.IndexOfAny(new[] {'\r', '\n', '\0'}) >= 0) throw new InvalidOperationException("invalid_existing_type_name");
                if (value.TryGetProperty("is_value_type", out var valueType) && valueType.ValueKind is not JsonValueKind.True and not JsonValueKind.False) throw new InvalidOperationException("invalid_existing_type_value_kind");
                return;
            case "szarray":
            case "byref":
            case "pointer":
                if (!HasExactProperties("kind", "element")) throw new InvalidOperationException("invalid_type_spec_properties");
                ValidateTypeSpec(Required("element"), depth + 1, false); return;
            case "array":
                if (!HasExactProperties("kind", "element", "rank")) throw new InvalidOperationException("invalid_type_spec_properties");
                if (!Required("rank").TryGetInt32(out var rank) || rank < 2 || rank > 8) throw new InvalidOperationException("invalid_array_rank");
                ValidateTypeSpec(Required("element"), depth + 1, false); return;
            case "generic_instance":
                if (!HasExactProperties("kind", "generic_type", "arguments")) throw new InvalidOperationException("invalid_type_spec_properties");
                ValidateTypeSpec(Required("generic_type"), depth + 1, true);
                var arguments = Required("arguments");
                if (arguments.ValueKind != JsonValueKind.Array || arguments.GetArrayLength() is < 1 or > 8) throw new InvalidOperationException("invalid_generic_arguments");
                foreach (var argument in arguments.EnumerateArray()) ValidateTypeSpec(argument, depth + 1, false);
                return;
            default: throw new InvalidOperationException("unsupported_type_spec");
        }
    }
    static TypeSig ResolveTypeSpec(ModuleDefMD module, JsonElement value) {
        ValidateTypeSpec(value, 0, false);
        if (value.ValueKind == JsonValueKind.String) return PrimitiveType(module, value.GetString()!);
        var kind = value.GetProperty("kind").GetString();
        return kind switch {
            "existing_type" => ResolveExistingTypeSig(module, value),
            "szarray" => new SZArraySig(ResolveTypeSpec(module, value.GetProperty("element"))),
            "array" => new ArraySig(ResolveTypeSpec(module, value.GetProperty("element")), value.GetProperty("rank").GetInt32()),
            "byref" => new ByRefSig(ResolveTypeSpec(module, value.GetProperty("element"))),
            "pointer" => new PtrSig(ResolveTypeSpec(module, value.GetProperty("element"))),
            "generic_instance" => new GenericInstSig(ResolveExistingTypeSig(module, value.GetProperty("generic_type")) as ClassOrValueTypeSig ?? throw new InvalidOperationException("generic_type_not_class_or_value"), value.GetProperty("arguments").EnumerateArray().Select(argument => ResolveTypeSpec(module, argument)).ToArray()),
            _ => throw new InvalidOperationException("unsupported_type_spec")
        };
    }
    static TypeSig ResolveExistingTypeSig(ModuleDefMD module, JsonElement value) {
        var reference = ResolveExistingTypeReference(module, value);
        var isValueType = value.TryGetProperty("is_value_type", out var valueType) && valueType.GetBoolean();
        return isValueType ? new ValueTypeSig(reference) : new ClassSig(reference);
    }
    static ITypeDefOrRef ResolveExistingTypeReference(ModuleDefMD module, JsonElement value) {
        ValidateTypeSpec(value, 0, true);
        var fullName = value.GetProperty("full_name").GetString()!;
        return module.GetTypes().Cast<ITypeDefOrRef>().Concat(module.GetTypeRefs()).FirstOrDefault(candidate => string.Equals(candidate.FullName, fullName, StringComparison.Ordinal)) ?? throw new InvalidOperationException("existing_type_not_in_module_metadata");
    }
    static string[] GetDecompilerLanguages() {
        return GetDecompilers().Select(item => item.GenericNameUI).Where(name => !string.IsNullOrWhiteSpace(name)).Distinct(StringComparer.Ordinal).OrderBy(name => name, StringComparer.Ordinal).ToArray();
    }
    static IDecompiler GetDecompiler(string requestedLanguage) {
        if (string.IsNullOrWhiteSpace(requestedLanguage) || requestedLanguage.Length > 80) throw new InvalidOperationException("invalid_decompiler_language");
        var language = GetDecompilers().FirstOrDefault(item => string.Equals(item.GenericNameUI, requestedLanguage, StringComparison.OrdinalIgnoreCase));
        return language ?? throw new InvalidOperationException("decompiler_language_unavailable");
    }
    static IEnumerable<IDecompiler> GetDecompilers() {
        var assembly = Assembly.Load("dnSpy.Decompiler.ILSpy.Core");
        foreach (var type in assembly.GetTypes()) {
            if (type.IsAbstract || type.IsInterface || !typeof(IDecompilerProvider).IsAssignableFrom(type)) continue;
            if (Activator.CreateInstance(type) is not IDecompilerProvider provider) continue;
            foreach (var decompiler in provider.Create()) yield return decompiler;
        }
    }
}
}
