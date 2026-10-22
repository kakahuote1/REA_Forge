package forge.recaf;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceClassVisitor;
import software.coley.recaf.info.JvmClassInfo;
import software.coley.recaf.info.builder.JvmClassInfoBuilder;
import software.coley.recaf.services.decompile.DecompileResult;
import software.coley.recaf.services.decompile.cfr.CfrConfig;
import software.coley.recaf.services.decompile.cfr.CfrDecompiler;
import software.coley.recaf.services.decompile.vineflower.VineflowerConfig;
import software.coley.recaf.services.decompile.vineflower.VineflowerDecompiler;
import software.coley.recaf.services.deobfuscation.transform.generic.DeadCodeRemovingTransformer;
import software.coley.recaf.util.visitors.DuplicateAnnotationRemovingVisitor;
import software.coley.recaf.services.assembler.AssemblerPipelineGeneralConfig;
import software.coley.recaf.services.assembler.JvmAssemblerPipeline;
import software.coley.recaf.services.assembler.JvmAssemblerPipelineConfig;
import software.coley.recaf.services.inheritance.InheritanceGraph;
import software.coley.recaf.services.transform.TransformationException;
import software.coley.recaf.services.workspace.BasicWorkspaceManager;
import software.coley.recaf.services.workspace.WorkspaceManagerConfig;
import software.coley.recaf.workspace.model.BasicWorkspace;
import software.coley.recaf.workspace.model.Workspace;
import software.coley.recaf.workspace.model.bundle.BasicJvmClassBundle;
import software.coley.recaf.workspace.model.resource.WorkspaceResource;
import software.coley.recaf.workspace.model.resource.WorkspaceResourceBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

/**
 * Narrow, local Recaf API worker. It deliberately has no listener, scripting, plugin,
 * GUI, process-attach, URL-import, or remote-JVM surface.
 */
public final class Worker {
    private static final Gson GSON = new Gson();
    private static final int MAX_INPUT_BYTES = 64 * 1024 * 1024;
    private static final int MAX_CLASSES = 4_000;
    private static final int MAX_RESPONSE_CHARS = 4 * 1024 * 1024;
    private static final int MAX_COMPILE_SET_SOURCES = 8;
    private static final int MAX_COMPILE_SET_BYTES = 1024 * 1024;
    private static final int MAX_COMPILE_SET_CLASSES = 32;
    private static final int MAX_DEPENDENCY_JARS = 4;
    private static final int MAX_DEPENDENCY_JAR_BYTES = 8 * 1024 * 1024;
    private static final int MAX_DEPENDENCY_ENTRIES = 1_024;
    private static final int MAX_DEPENDENCY_CLASSES = 512;
    private static final long MAX_DEPENDENCY_TOTAL_BYTES = 16L * 1024 * 1024;
    private static final int MAX_DEPENDENCY_CLASS_BYTES = 2 * 1024 * 1024;
    private static final Pattern PACKAGE_DECLARATION = Pattern.compile("(?m)^\\s*package\\s+([A-Za-z_$][A-Za-z0-9_$.]*)\\s*;");

    private Worker() {
    }

    public static void main(String[] args) {
        try {
            JsonObject request = JsonParser.parseReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).getAsJsonObject();
            String expectedToken = System.getenv("REA_FORGE_JAVA_TOKEN");
            String suppliedToken = requireString(request, "token", 256);
            if (expectedToken == null || !MessageDigest.isEqual(expectedToken.getBytes(StandardCharsets.UTF_8), suppliedToken.getBytes(StandardCharsets.UTF_8))) {
                fail("unauthorized");
                return;
            }
            String operation = requireString(request, "operation", 32);
            JsonObject data = switch (operation) {
                case "status" -> status();
                case "inspect" -> inspect(requireWorkspaceInput(request));
                case "diff" -> diff(requireWorkspaceInput(request, "left_path"), requireWorkspaceInput(request, "right_path"));
                case "decompile" -> decompile(requireWorkspaceInput(request), requireClassName(request), requireEngine(request));
                case "disassemble" -> disassemble(requireWorkspaceInput(request), requireClassName(request));
                case "export_class" -> exportClass(requireWorkspaceInput(request), requireWorkspaceOutput(request), requireClassName(request));
                case "rename_class" -> renameClass(requireWorkspaceInput(request), requireWorkspaceOutput(request), requireClassName(request), requireClassName(request, "new_class_name"));
                case "rename_method" -> renameMethod(requireWorkspaceInput(request), requireWorkspaceOutput(request), requireClassName(request), requireMemberName(request, "method_name"), requireMethodDescriptor(request), requireMemberName(request, "new_name"));
                case "rename_field" -> renameField(requireWorkspaceInput(request), requireWorkspaceOutput(request), requireClassName(request), requireMemberName(request, "field_name"), requireFieldDescriptor(request), requireMemberName(request, "new_name"));
                case "search" -> search(requireWorkspaceInput(request), requireSearchQuery(request), requireSearchKind(request));
                case "call_graph" -> callGraph(requireWorkspaceInput(request), requireClassName(request), requireMemberName(request, "method_name"), requireMethodDescriptor(request));
                case "transform" -> transform(requireWorkspaceInput(request), requireWorkspaceOutput(request), requireTransformer(request));
                case "compile_java" -> compileJava(requireWorkspaceJavaSource(request), requireWorkspaceOutput(request), requireClassName(request), requireJavaRelease(request));
                case "compile_java_set" -> compileJavaSet(requireWorkspaceJavaSources(request), requireWorkspaceDependencyJars(request), requireWorkspaceOutput(request), requireClassName(request), requireJavaRelease(request));
                case "assemble" -> assemble(requireWorkspaceInput(request), requireWorkspaceOutput(request), requireClassName(request), requireWorkspaceAssemblySource(request));
                default -> throw new IllegalArgumentException("operation is not allowed");
            };
            succeed(data);
        } catch (Exception exception) {
            fail("rejected");
        }
    }

    private static JsonObject status() {
        JsonObject data = new JsonObject();
        data.addProperty("worker", "rea-forge-recaf");
        data.addProperty("mode", "single_request_no_listener");
        data.addProperty("recaf_surface", "core_api_only");
        return data;
    }

    private static JsonObject inspect(Path input) throws IOException {
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JsonArray classArray = new JsonArray();
        for (JvmClassInfo info : classes.values()) {
            JsonObject item = new JsonObject();
            item.addProperty("name", info.getName());
            item.addProperty("super_name", info.getSuperName());
            JsonArray interfaces = new JsonArray();
            info.getInterfaces().forEach(interfaces::add);
            item.add("interfaces", interfaces);
            item.addProperty("method_count", info.getMethods().size());
            item.addProperty("field_count", info.getFields().size());
            JsonArray methods = new JsonArray();
            info.getMethods().stream().limit(2_048).forEach(method -> {
                JsonObject member = new JsonObject();
                member.addProperty("name", method.getName());
                member.addProperty("descriptor", method.getDescriptor());
                member.addProperty("access", method.getAccess());
                methods.add(member);
            });
            item.add("methods", methods);
            JsonArray fields = new JsonArray();
            info.getFields().stream().limit(2_048).forEach(field -> {
                JsonObject member = new JsonObject();
                member.addProperty("name", field.getName());
                member.addProperty("descriptor", field.getDescriptor());
                member.addProperty("access", field.getAccess());
                fields.add(member);
            });
            item.add("fields", fields);
            item.addProperty("bytecode_size", info.getBytecode().length);
            JsonArray references = new JsonArray();
            info.getReferencedClasses().stream().limit(512).forEach(references::add);
            item.add("references", references);
            JsonArray strings = new JsonArray();
            info.getStringConstants().stream().sorted().limit(512).forEach(strings::add);
            item.add("string_constants", strings);
            classArray.add(item);
        }
        JsonObject data = new JsonObject();
        data.addProperty("input_kind", input.toString().toLowerCase().endsWith(".class") ? "class" : "archive");
        data.addProperty("class_count", classes.size());
        data.add("classes", classArray);
        return data;
    }

    private static JsonObject diff(Path left, Path right) throws IOException {
        Map<String, JvmClassInfo> leftClasses = loadClasses(left);
        Map<String, JvmClassInfo> rightClasses = loadClasses(right);
        JsonArray onlyLeft = new JsonArray();
        JsonArray onlyRight = new JsonArray();
        JsonArray changed = new JsonArray();
        int changedCount = 0;
        for (String className : leftClasses.keySet().stream().sorted().toList()) {
            JvmClassInfo leftClass = leftClasses.get(className);
            JvmClassInfo rightClass = rightClasses.get(className);
            if (rightClass == null) {
                if (onlyLeft.size() < 512) {
                    onlyLeft.add(className);
                }
                continue;
            }
            if (!MessageDigest.isEqual(leftClass.getBytecode(), rightClass.getBytecode())) {
                changedCount++;
                if (changed.size() < 512) {
                    JsonObject item = new JsonObject();
                    item.addProperty("class_name", className);
                    item.addProperty("left_sha256", sha256(leftClass.getBytecode()));
                    item.addProperty("right_sha256", sha256(rightClass.getBytecode()));
                    item.addProperty("left_method_count", leftClass.getMethods().size());
                    item.addProperty("right_method_count", rightClass.getMethods().size());
                    item.addProperty("left_field_count", leftClass.getFields().size());
                    item.addProperty("right_field_count", rightClass.getFields().size());
                    changed.add(item);
                }
            }
        }
        for (String className : rightClasses.keySet().stream().sorted().toList()) {
            if (!leftClasses.containsKey(className) && onlyRight.size() < 512) {
                onlyRight.add(className);
            }
        }
        JsonObject data = new JsonObject();
        data.addProperty("left_path", left.toString());
        data.addProperty("right_path", right.toString());
        data.addProperty("left_sha256", sha256(left));
        data.addProperty("right_sha256", sha256(right));
        data.addProperty("left_class_count", leftClasses.size());
        data.addProperty("right_class_count", rightClasses.size());
        data.addProperty("changed_class_count", changedCount);
        data.addProperty("truncated", onlyLeft.size() < leftClasses.size() - rightClasses.size() || onlyRight.size() < rightClasses.size() - leftClasses.size() || changed.size() < changedCount);
        data.add("only_left", onlyLeft);
        data.add("only_right", onlyRight);
        data.add("changed_classes", changed);
        return data;
    }

    private static JsonObject decompile(Path input, String className, String engine) throws IOException {
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JvmClassInfo info = classes.get(className);
        if (info == null) {
            throw new IllegalArgumentException("class not present in workspace input");
        }
        Workspace workspace = buildWorkspace(classes);
        DecompileResult result;
        if ("cfr".equals(engine)) {
            BasicWorkspaceManager manager = new BasicWorkspaceManager(new WorkspaceManagerConfig());
            result = new CfrDecompiler(manager, new CfrConfig()).decompile(workspace, info);
        } else if ("vineflower".equals(engine)) {
            result = new VineflowerDecompiler(new VineflowerConfig()).decompile(workspace, info);
        } else {
            throw new IllegalArgumentException("engine is not allowed");
        }
        if (result.getText() == null || result.getText().length() > MAX_RESPONSE_CHARS) {
            throw new IllegalArgumentException("decompiler produced no bounded text output");
        }
        JsonObject data = new JsonObject();
        data.addProperty("engine", engine);
        data.addProperty("class_name", className);
        data.addProperty("result_type", result.getType().name());
        data.addProperty("source", result.getText());
        return data;
    }

    private static JsonObject disassemble(Path input, String className) throws IOException {
        JvmClassInfo info = loadClasses(input).get(className);
        if (info == null) {
            throw new IllegalArgumentException("class not present in workspace input");
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintWriter writer = new PrintWriter(bytes, true, StandardCharsets.UTF_8)) {
            new ClassReader(info.getBytecode()).accept(new TraceClassVisitor(null, new Textifier(), writer), 0);
        }
        String text = bytes.toString(StandardCharsets.UTF_8);
        if (text.length() > MAX_RESPONSE_CHARS) {
            throw new IllegalArgumentException("disassembly exceeded bounded text output");
        }
        JsonObject data = new JsonObject();
        data.addProperty("class_name", className);
        data.addProperty("assembly", text);
        return data;
    }

    private static JsonObject exportClass(Path input, Path output, String className) throws IOException {
        if (!output.getFileName().toString().toLowerCase().endsWith(".class")) {
            throw new IllegalArgumentException("class export only writes a new class file");
        }
        JvmClassInfo selected = loadClasses(input).get(className);
        if (selected == null || selected.getBytecode().length == 0 || selected.getBytecode().length > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("class export target is not present in the input");
        }
        Files.write(output, selected.getBytecode(), StandardOpenOption.CREATE_NEW);
        JvmClassInfo verified = loadClasses(output).get(className);
        if (verified == null || !MessageDigest.isEqual(selected.getBytecode(), verified.getBytecode())) {
            throw new IllegalArgumentException("class export output did not retain the requested class");
        }
        JsonObject data = new JsonObject();
        data.addProperty("class_name", className);
        data.addProperty("source_sha256", sha256(input));
        data.addProperty("output_path", output.toString());
        data.addProperty("output_sha256", sha256(output));
        data.addProperty("classfile_major", new ClassReader(selected.getBytecode()).readUnsignedShort(6));
        return data;
    }

    private static JsonObject renameClass(Path input, Path output, String className, String newClassName) throws IOException {
        Map<String, JvmClassInfo> classes = loadClasses(input);
        if (!classes.containsKey(className) || classes.containsKey(newClassName)) {
            throw new IllegalArgumentException("class mapping is not applicable to this input");
        }
        String inputName = input.getFileName().toString().toLowerCase();
        if (inputName.endsWith(".class")) {
            Files.write(output, remapClass(Files.readAllBytes(input), Map.of(className, newClassName)), StandardOpenOption.CREATE_NEW);
        } else {
            try (ZipFile archive = new ZipFile(input.toFile()); ZipOutputStream target = new ZipOutputStream(Files.newOutputStream(output, StandardOpenOption.CREATE_NEW))) {
                var entries = archive.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry sourceEntry = entries.nextElement();
                    String targetName = sourceEntry.getName().equals(className + ".class") ? newClassName + ".class" : sourceEntry.getName();
                    ZipEntry targetEntry = new ZipEntry(targetName);
                    target.putNextEntry(targetEntry);
                    if (!sourceEntry.isDirectory()) {
                        try (var stream = archive.getInputStream(sourceEntry)) {
                            byte[] content = readBounded(stream);
                            if (sourceEntry.getName().endsWith(".class")) {
                                content = remapClass(content, Map.of(className, newClassName));
                            }
                            target.write(content);
                        }
                    }
                    target.closeEntry();
                }
            }
        }
        if (!loadClasses(output).containsKey(newClassName)) {
            throw new IllegalArgumentException("derived output did not retain the mapped class");
        }
        JsonObject data = new JsonObject();
        data.addProperty("class_name_before", className);
        data.addProperty("class_name_after", newClassName);
        data.addProperty("output_path", output.toString());
        data.addProperty("output_sha256", sha256(output));
        return data;
    }

    private static JsonObject search(Path input, String query, String kind) throws IOException {
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JsonArray matches = new JsonArray();
        String normalizedClassQuery = query.replace('.', '/');
        for (JvmClassInfo info : classes.values()) {
            if (("any".equals(kind) || "class_name".equals(kind)) && info.getName().contains(normalizedClassQuery)) {
                addSearchMatch(matches, info.getName(), "class_name", info.getName());
            }
            if ("any".equals(kind) || "member_name".equals(kind)) {
                info.getMethods().stream().filter(member -> member.getName().contains(query)).forEach(member -> addSearchMatch(matches, info.getName(), "method", member.getName() + member.getDescriptor()));
                info.getFields().stream().filter(member -> member.getName().contains(query)).forEach(member -> addSearchMatch(matches, info.getName(), "field", member.getName() + ":" + member.getDescriptor()));
            }
            if ("any".equals(kind) || "string_constant".equals(kind)) {
                info.getStringConstants().stream().filter(value -> value.contains(query)).forEach(value -> addSearchMatch(matches, info.getName(), "string_constant", value));
            }
            if ("any".equals(kind) || "reference".equals(kind)) {
                info.getReferencedClasses().stream().filter(value -> value.contains(normalizedClassQuery)).forEach(value -> addSearchMatch(matches, info.getName(), "reference", value));
            }
        }
        JsonObject data = new JsonObject();
        data.addProperty("query", query);
        data.addProperty("kind", kind);
        data.addProperty("match_count", matches.size());
        data.add("matches", matches);
        return data;
    }

    private static void addSearchMatch(JsonArray matches, String className, String category, String value) {
        if (matches.size() >= 2_048) {
            return;
        }
        JsonObject item = new JsonObject();
        item.addProperty("class_name", className);
        item.addProperty("category", category);
        item.addProperty("value", value);
        matches.add(item);
    }

    private static JsonObject callGraph(Path input, String className, String methodName, String descriptor) throws IOException {
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JvmClassInfo selected = classes.get(className);
        if (selected == null || selected.getMethods().stream().noneMatch(method -> method.getName().equals(methodName) && method.getDescriptor().equals(descriptor))) {
            throw new IllegalArgumentException("call graph target is not present in the input");
        }
        JsonArray outgoing = new JsonArray();
        JsonArray incoming = new JsonArray();
        for (JvmClassInfo info : classes.values()) {
            new ClassReader(info.getBytecode()).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String methodDescriptor, String signature, String[] exceptions) {
                    boolean isTarget = info.getName().equals(className) && name.equals(methodName) && methodDescriptor.equals(descriptor);
                    return new MethodVisitor(Opcodes.ASM9) {
                        @Override
                        public void visitMethodInsn(int opcode, String owner, String invokedName, String invokedDescriptor, boolean isInterface) {
                            if (isTarget && outgoing.size() < 2_048) {
                                addCall(outgoing, owner, invokedName, invokedDescriptor, "invoke");
                            }
                            if (owner.equals(className) && invokedName.equals(methodName) && invokedDescriptor.equals(descriptor) && incoming.size() < 2_048) {
                                addCall(incoming, info.getName(), name, methodDescriptor, "caller");
                            }
                        }

                        @Override
                        public void visitInvokeDynamicInsn(String invokedName, String invokedDescriptor, org.objectweb.asm.Handle bootstrapMethodHandle, Object... bootstrapMethodArguments) {
                            if (isTarget && outgoing.size() < 2_048) {
                                addCall(outgoing, "<invokedynamic>", invokedName, invokedDescriptor, "invokedynamic");
                            }
                        }
                    };
                }
            }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        }
        JsonObject data = new JsonObject();
        data.addProperty("class_name", className);
        data.addProperty("method_name", methodName);
        data.addProperty("descriptor", descriptor);
        data.add("outgoing", outgoing);
        data.add("incoming", incoming);
        return data;
    }

    private static void addCall(JsonArray calls, String owner, String name, String descriptor, String kind) {
        JsonObject item = new JsonObject();
        item.addProperty("owner", owner);
        item.addProperty("name", name);
        item.addProperty("descriptor", descriptor);
        item.addProperty("kind", kind);
        calls.add(item);
    }

    private static JsonObject transform(Path input, Path output, String transformer) throws IOException {
        int[] instructionCounts = new int[2];
        int[] classAnnotationCounts = new int[2];
        int[] transformedClasses = new int[1];
        writeTransformedInput(input, output, transformer, instructionCounts, classAnnotationCounts, transformedClasses);
        Map<String, JvmClassInfo> verified = loadClasses(output);
        JsonObject data = new JsonObject();
        data.addProperty("transformer", transformer);
        data.addProperty("class_count", verified.size());
        data.addProperty("changed_class_count", transformedClasses[0]);
        data.addProperty("instruction_count_before", instructionCounts[0]);
        data.addProperty("instruction_count_after", instructionCounts[1]);
        data.addProperty("class_annotation_count_before", classAnnotationCounts[0]);
        data.addProperty("class_annotation_count_after", classAnnotationCounts[1]);
        data.addProperty("output_path", output.toString());
        data.addProperty("output_sha256", sha256(output));
        return data;
    }

    private static JsonObject assemble(Path input, Path output, String className, Path assemblySource) throws IOException {
        String inputName = input.getFileName().toString().toLowerCase();
        String outputName = output.getFileName().toString().toLowerCase();
        boolean classInput = inputName.endsWith(".class");
        boolean archiveInput = inputName.endsWith(".jar") || inputName.endsWith(".war");
        if ((!classInput && !archiveInput) || (classInput && !outputName.endsWith(".class")) || (archiveInput && !inputName.substring(inputName.lastIndexOf('.')).equals(outputName.substring(outputName.lastIndexOf('.'))))) {
            throw new IllegalArgumentException("assembler input and output types are not compatible");
        }
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JvmClassInfo original = classes.get(className);
        if (original == null) {
            throw new IllegalArgumentException("class not present in workspace input");
        }
        String source = Files.readString(assemblySource, StandardCharsets.UTF_8);
        if (source.indexOf('\0') >= 0 || source.length() > 512 * 1024) {
            throw new IllegalArgumentException("assembly source is outside the worker bound");
        }
        Workspace workspace = buildWorkspace(classes);
        var classPath = workspace.findJvmClass(className);
        if (classPath == null) {
            throw new IllegalArgumentException("assembly target is unavailable in workspace");
        }
        JvmAssemblerPipeline pipeline = new JvmAssemblerPipeline(
                workspace,
                new InheritanceGraph(workspace),
                new AssemblerPipelineGeneralConfig(),
                new JvmAssemblerPipelineConfig());
        var tokens = pipeline.tokenize(source, "workspace-assembly");
        if (!tokens.isOk()) {
            throw new IllegalArgumentException("assembly tokenizer rejected source");
        }
        var elements = pipeline.fullParse(tokens.get());
        if (!elements.isOk()) {
            throw new IllegalArgumentException("assembly parser rejected source");
        }
        var assembled = pipeline.assembleAndWrap(elements.get(), classPath);
        if (!assembled.isOk()) {
            throw new IllegalArgumentException("assembly compiler rejected source");
        }
        JvmClassInfo assembledInfo = assembled.get();
        byte[] bytecode = assembledInfo.getBytecode();
        if (!className.equals(assembledInfo.getName()) || bytecode.length == 0 || bytecode.length > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("assembled class does not satisfy the bounded target contract");
        }
        new JvmClassInfoBuilder(bytecode).build();
        if (classInput) {
            Files.write(output, bytecode, StandardOpenOption.CREATE_NEW);
        } else {
            writeAssembledArchive(input, output, className, bytecode);
        }
        if (!loadClasses(output).containsKey(className)) {
            throw new IllegalArgumentException("assembled output does not contain the requested class");
        }
        JsonObject data = new JsonObject();
        data.addProperty("assembler", "recaf_jasm_pipeline");
        data.addProperty("class_name", assembledInfo.getName());
        data.addProperty("input_kind", classInput ? "class" : "archive");
        data.addProperty("assembly_source_sha256", sha256(assemblySource));
        data.addProperty("classfile_major", new ClassReader(bytecode).readUnsignedShort(6));
        data.addProperty("output_path", output.toString());
        data.addProperty("output_sha256", sha256(output));
        return data;
    }

    private static void writeAssembledArchive(Path input, Path output, String className, byte[] bytecode) throws IOException {
        Path temporary = Files.createTempFile(output.getParent(), ".rea-forge-assemble-", ".tmp");
        int targetEntries = 0;
        try {
            try (ZipFile archive = new ZipFile(input.toFile()); ZipOutputStream target = new ZipOutputStream(Files.newOutputStream(temporary, StandardOpenOption.TRUNCATE_EXISTING))) {
                var entries = archive.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry sourceEntry = entries.nextElement();
                    String entryName = sourceEntry.getName();
                    boolean targetClass = entryName.equals(className + ".class");
                    if (targetClass && ++targetEntries > 1) {
                        throw new IllegalArgumentException("archive has duplicate assembler target entries");
                    }
                    target.putNextEntry(new ZipEntry(entryName));
                    if (!sourceEntry.isDirectory()) {
                        if (targetClass) {
                            target.write(bytecode);
                        } else {
                            try (var stream = archive.getInputStream(sourceEntry)) {
                                target.write(readBounded(stream));
                            }
                        }
                    }
                    target.closeEntry();
                }
            }
            if (targetEntries != 1) {
                throw new IllegalArgumentException("archive does not contain exactly one assembler target entry");
            }
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, output);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void writeTransformedInput(Path input, Path output, String transformer, int[] instructionCounts, int[] classAnnotationCounts, int[] transformedClasses) throws IOException {
        String inputName = input.getFileName().toString().toLowerCase();
        if (inputName.endsWith(".class")) {
            Files.write(output, transformClass(Files.readAllBytes(input), transformer, instructionCounts, classAnnotationCounts, transformedClasses), StandardOpenOption.CREATE_NEW);
            return;
        }
        try (ZipFile archive = new ZipFile(input.toFile()); ZipOutputStream target = new ZipOutputStream(Files.newOutputStream(output, StandardOpenOption.CREATE_NEW))) {
            var entries = archive.entries();
            while (entries.hasMoreElements()) {
                ZipEntry sourceEntry = entries.nextElement();
                target.putNextEntry(new ZipEntry(sourceEntry.getName()));
                if (!sourceEntry.isDirectory()) {
                    try (var stream = archive.getInputStream(sourceEntry)) {
                        byte[] content = readBounded(stream);
                        if (sourceEntry.getName().endsWith(".class")) {
                            content = transformClass(content, transformer, instructionCounts, classAnnotationCounts, transformedClasses);
                        }
                        target.write(content);
                    }
                }
                target.closeEntry();
            }
        }
    }

    private static byte[] transformClass(byte[] input, String transformer, int[] instructionCounts, int[] classAnnotationCounts, int[] transformedClasses) throws IOException {
        if (!("dead_code_remove".equals(transformer) || "duplicate_annotation_remove".equals(transformer))) {
            throw new IllegalArgumentException("transformer is not allowed");
        }
        ClassReader reader = new ClassReader(input);
        ClassNode node = new ClassNode();
        reader.accept(node, 0);
        int before = instructionCount(node);
        int annotationsBefore = classAnnotationCount(input);
        boolean changed = false;
        byte[] transformedBytes = input;
        if ("dead_code_remove".equals(transformer)) {
            DeadCodeRemovingTransformer deadCode = new DeadCodeRemovingTransformer();
            try {
                for (var method : node.methods) {
                    changed |= deadCode.prune(node, method);
                }
            } catch (TransformationException exception) {
                throw new IOException("Recaf transformer rejected the class", exception);
            }
            if (changed) {
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
                node.accept(writer);
                transformedBytes = writer.toByteArray();
            }
        } else {
            ClassWriter writer = new ClassWriter(reader, 0);
            DuplicateAnnotationRemovingVisitor duplicateRemover = new DuplicateAnnotationRemovingVisitor(writer);
            reader.accept(duplicateRemover, 0);
            changed = duplicateRemover.hasDetectedDuplicateAnnotations();
            if (changed) {
                transformedBytes = writer.toByteArray();
            }
        }
        int after = instructionCount(node);
        instructionCounts[0] += before;
        instructionCounts[1] += after;
        classAnnotationCounts[0] += annotationsBefore;
        classAnnotationCounts[1] += classAnnotationCount(transformedBytes);
        if (!changed) {
            return input;
        }
        transformedClasses[0]++;
        return transformedBytes;
    }

    private static int classAnnotationCount(byte[] bytecode) throws IOException {
        int[] count = new int[1];
        try {
            new ClassReader(bytecode).accept(new ClassVisitor(Opcodes.ASM9) {
                @Override
                public org.objectweb.asm.AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                    count[0]++;
                    return super.visitAnnotation(descriptor, visible);
                }
            }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid class annotation structure", exception);
        }
        return count[0];
    }

    private static int instructionCount(ClassNode node) {
        int count = 0;
        for (var method : node.methods) {
            count += method.instructions.size();
        }
        return count;
    }

    private static JsonObject compileJava(Path sourcePath, Path output, String className, int release) throws IOException {
        String source = Files.readString(sourcePath, StandardCharsets.UTF_8);
        if (source.length() > 512 * 1024 || source.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Java source is outside the worker limit");
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("fixed JDK compiler is unavailable");
        }
        String binaryName = className.replace('/', '.');
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager standard = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            standard.setLocationFromPaths(StandardLocation.CLASS_PATH, List.of());
            MemoryJavaFileManager manager = new MemoryJavaFileManager(standard);
            JavaFileObject unit = new MemoryJavaSource(binaryName, source);
            Boolean succeeded = compiler.getTask(null, manager, diagnostics, List.of("--release", Integer.toString(release), "-proc:none", "-implicit:none", "-g:none"), null, List.of(unit)).call();
            JsonObject data = new JsonObject();
            data.addProperty("class_name", className);
            data.addProperty("release", release);
            data.add("diagnostics", compileDiagnostics(diagnostics));
            if (!Boolean.TRUE.equals(succeeded) || manager.classCount() != 1 || !manager.hasClass(binaryName)) {
                data.addProperty("compiled", false);
                data.addProperty("output_written", false);
                return data;
            }
            byte[] bytecode = manager.classBytes(binaryName);
            if (bytecode.length == 0 || bytecode.length > MAX_INPUT_BYTES) {
                throw new IllegalArgumentException("compiled output is outside the worker limit");
            }
            JvmClassInfo verified = new JvmClassInfoBuilder(bytecode).build();
            if (!className.equals(verified.getName())) {
                throw new IllegalArgumentException("compiled output class name does not match the request");
            }
            Files.write(output, bytecode, StandardOpenOption.CREATE_NEW);
            data.addProperty("compiled", true);
            data.addProperty("output_written", true);
            data.addProperty("output_path", output.toString());
            data.addProperty("output_sha256", sha256(output));
            data.addProperty("classfile_major", new ClassReader(bytecode).readUnsignedShort(6));
            return data;
        }
    }

    private static JsonObject compileJavaSet(List<Path> sourcePaths, List<Path> dependencyPaths, Path output, String entryClassName, int release) throws IOException {
        if (!output.getFileName().toString().toLowerCase().endsWith(".jar")) {
            throw new IllegalArgumentException("multi-source compilation only writes a new jar");
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("fixed JDK compiler is unavailable");
        }
        List<DependencyJar> dependencies = verifyDependencyJars(dependencyPaths, release);
        long totalSourceBytes = 0;
        Set<String> sourceNames = new HashSet<>();
        List<JavaFileObject> units = new ArrayList<>();
        for (Path sourcePath : sourcePaths) {
            String source = Files.readString(sourcePath, StandardCharsets.UTF_8);
            totalSourceBytes += source.length();
            if (source.indexOf('\0') >= 0 || totalSourceBytes > MAX_COMPILE_SET_BYTES) {
                throw new IllegalArgumentException("multi-source Java input is outside the worker limit");
            }
            String binaryName = sourceBinaryName(sourcePath, source);
            if (!sourceNames.add(binaryName)) {
                throw new IllegalArgumentException("multi-source Java input has duplicate binary names");
            }
            units.add(new MemoryJavaSource(binaryName, source));
        }
        String entryBinaryName = entryClassName.replace('/', '.');
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager standard = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            standard.setLocationFromPaths(StandardLocation.CLASS_PATH, dependencyPaths);
            MemoryJavaFileManager manager = new MemoryJavaFileManager(standard);
            Boolean succeeded = compiler.getTask(null, manager, diagnostics, List.of("--release", Integer.toString(release), "-proc:none", "-implicit:none", "-g:none"), null, units).call();
            JsonObject data = new JsonObject();
            data.addProperty("entry_class_name", entryClassName);
            data.addProperty("release", release);
            data.addProperty("source_count", sourcePaths.size());
            data.add("dependency_sha256", dependencyHashes(dependencies));
            data.add("diagnostics", compileDiagnostics(diagnostics));
            if (!Boolean.TRUE.equals(succeeded) || manager.classCount() < 2 || manager.classCount() > MAX_COMPILE_SET_CLASSES || !manager.hasClass(entryBinaryName)) {
                data.addProperty("compiled", false);
                data.addProperty("output_written", false);
                return data;
            }
            Map<String, byte[]> compiledClasses = manager.compiledClasses();
            for (Map.Entry<String, byte[]> entry : compiledClasses.entrySet()) {
                byte[] bytecode = entry.getValue();
                if (bytecode.length == 0 || bytecode.length > MAX_INPUT_BYTES) {
                    throw new IllegalArgumentException("multi-source compiled class is outside the worker limit");
                }
                JvmClassInfo verified = new JvmClassInfoBuilder(bytecode).build();
                if (!entry.getKey().replace('.', '/').equals(verified.getName())) {
                    throw new IllegalArgumentException("multi-source compiled class name does not match its output entry");
                }
            }
            if (!dependencies.equals(verifyDependencyJars(dependencyPaths, release))) {
                throw new IllegalArgumentException("dependency JAR changed during compilation");
            }
            writeCompiledArchive(output, compiledClasses);
            Map<String, JvmClassInfo> verifiedOutput = loadClasses(output);
            if (verifiedOutput.size() != compiledClasses.size() || !verifiedOutput.containsKey(entryClassName)) {
                throw new IllegalArgumentException("multi-source jar output is incomplete");
            }
            data.addProperty("compiled", true);
            data.addProperty("output_written", true);
            data.addProperty("class_count", compiledClasses.size());
            data.addProperty("output_path", output.toString());
            data.addProperty("output_sha256", sha256(output));
            return data;
        }
    }

    private static List<DependencyJar> verifyDependencyJars(List<Path> dependencyPaths, int release) throws IOException {
        List<DependencyJar> result = new ArrayList<>();
        long totalBytes = 0;
        int totalClasses = 0;
        int maximumMajor = maximumClassfileMajor(release);
        for (Path dependency : dependencyPaths) {
            Set<String> names = new HashSet<>();
            int classCount = 0;
            try (ZipFile archive = new ZipFile(dependency.toFile())) {
                var entries = archive.entries();
                int entryCount = 0;
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    entryCount++;
                    if (entryCount > MAX_DEPENDENCY_ENTRIES || !names.add(entry.getName()) || !isPermittedDependencyEntry(entry)) {
                        throw new IllegalArgumentException("dependency JAR entry is outside the worker policy");
                    }
                    if (!entry.getName().endsWith(".class")) {
                        continue;
                    }
                    byte[] bytecode;
                    try (InputStream input = archive.getInputStream(entry)) {
                        bytecode = readBounded(input, MAX_DEPENDENCY_CLASS_BYTES);
                    }
                    totalBytes += bytecode.length;
                    if (totalBytes > MAX_DEPENDENCY_TOTAL_BYTES || ++classCount > MAX_DEPENDENCY_CLASSES || ++totalClasses > MAX_DEPENDENCY_CLASSES) {
                        throw new IllegalArgumentException("dependency JAR exceeds the worker limit");
                    }
                    ClassReader reader = new ClassReader(bytecode);
                    if (reader.readUnsignedShort(6) > maximumMajor || !entry.getName().equals(reader.getClassName() + ".class")) {
                        throw new IllegalArgumentException("dependency class is incompatible with the requested release");
                    }
                    new JvmClassInfoBuilder(bytecode).build();
                }
            }
            if (classCount == 0) {
                throw new IllegalArgumentException("dependency JAR has no permitted classes");
            }
            result.add(new DependencyJar(dependency, sha256(dependency), classCount));
        }
        return result;
    }

    private static boolean isPermittedDependencyEntry(ZipEntry entry) {
        String name = entry.getName();
        if (name.indexOf('\\') >= 0 || name.startsWith("/") || name.contains("../") || name.contains("//")) {
            return false;
        }
        return entry.isDirectory() || name.equals("META-INF/MANIFEST.MF") || name.endsWith(".class");
    }

    private static byte[] readBounded(InputStream input, int maximumBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8_192];
        while (true) {
            int read = input.read(buffer);
            if (read < 0) {
                return output.toByteArray();
            }
            if (output.size() > maximumBytes - read) {
                throw new IllegalArgumentException("dependency class is outside the worker limit");
            }
            output.write(buffer, 0, read);
        }
    }

    private static int maximumClassfileMajor(int release) {
        return switch (release) {
            case 8 -> 52;
            case 11 -> 55;
            case 17 -> 61;
            case 21 -> 65;
            case 25 -> 69;
            default -> throw new IllegalArgumentException("release is outside the worker policy");
        };
    }

    private static JsonArray dependencyHashes(List<DependencyJar> dependencies) {
        JsonArray result = new JsonArray();
        for (DependencyJar dependency : dependencies) {
            result.add(dependency.sha256());
        }
        return result;
    }

    private record DependencyJar(Path path, String sha256, int classCount) {}

    private static String sourceBinaryName(Path sourcePath, String source) {
        String filename = sourcePath.getFileName().toString();
        String simpleName = filename.substring(0, filename.length() - ".java".length());
        if (!simpleName.matches("[A-Za-z_$][A-Za-z0-9_$]*")) {
            throw new IllegalArgumentException("multi-source Java filename is malformed");
        }
        Matcher matcher = PACKAGE_DECLARATION.matcher(source);
        return matcher.find() ? matcher.group(1) + "." + simpleName : simpleName;
    }

    private static void writeCompiledArchive(Path output, Map<String, byte[]> classes) throws IOException {
        Path temporary = Files.createTempFile(output.getParent(), ".rea-forge-compile-", ".tmp");
        try {
            try (ZipOutputStream target = new ZipOutputStream(Files.newOutputStream(temporary, StandardOpenOption.TRUNCATE_EXISTING))) {
                for (String binaryName : classes.keySet().stream().sorted().toList()) {
                    target.putNextEntry(new ZipEntry(binaryName.replace('.', '/') + ".class"));
                    target.write(classes.get(binaryName));
                    target.closeEntry();
                }
            }
            try {
                Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, output);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static JsonArray compileDiagnostics(DiagnosticCollector<JavaFileObject> diagnostics) {
        JsonArray result = new JsonArray();
        for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
            if (result.size() >= 64) {
                break;
            }
            JsonObject item = new JsonObject();
            item.addProperty("kind", diagnostic.getKind().name());
            item.addProperty("line", diagnostic.getLineNumber());
            item.addProperty("column", diagnostic.getColumnNumber());
            String message = diagnostic.getMessage(java.util.Locale.ROOT);
            item.addProperty("message", message.length() > 1_024 ? message.substring(0, 1_024) : message);
            result.add(item);
        }
        return result;
    }

    private static JsonObject renameMethod(Path input, Path output, String className, String methodName, String descriptor, String newName) throws IOException {
        if (methodName.startsWith("<") || newName.startsWith("<")) {
            throw new IllegalArgumentException("constructors and class initializers cannot be renamed");
        }
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JvmClassInfo selected = classes.get(className);
        if (selected == null || selected.getMethods().stream().noneMatch(method -> method.getName().equals(methodName) && method.getDescriptor().equals(descriptor))) {
            throw new IllegalArgumentException("method mapping is not applicable to this input");
        }
        writeRemappedInput(input, output, Map.of(className + "." + methodName + descriptor, newName), null, null);
        JvmClassInfo verified = loadClasses(output).get(className);
        if (verified == null || verified.getMethods().stream().noneMatch(method -> method.getName().equals(newName) && method.getDescriptor().equals(descriptor))) {
            throw new IllegalArgumentException("derived output did not retain the mapped method");
        }
        return mappingData("method", className + "." + methodName + descriptor, newName, output);
    }

    private static JsonObject renameField(Path input, Path output, String className, String fieldName, String descriptor, String newName) throws IOException {
        Map<String, JvmClassInfo> classes = loadClasses(input);
        JvmClassInfo selected = classes.get(className);
        if (selected == null || selected.getFields().stream().noneMatch(field -> field.getName().equals(fieldName) && field.getDescriptor().equals(descriptor))) {
            throw new IllegalArgumentException("field mapping is not applicable to this input");
        }
        writeRemappedInput(input, output, Map.of("field:" + className + "." + fieldName + ":" + descriptor, newName), null, null);
        JvmClassInfo verified = loadClasses(output).get(className);
        if (verified == null || verified.getFields().stream().noneMatch(field -> field.getName().equals(newName) && field.getDescriptor().equals(descriptor))) {
            throw new IllegalArgumentException("derived output did not retain the mapped field");
        }
        return mappingData("field", className + "." + fieldName + ":" + descriptor, newName, output);
    }

    private static void writeRemappedInput(Path input, Path output, Map<String, String> mappings, String oldClassEntry, String newClassEntry) throws IOException {
        String inputName = input.getFileName().toString().toLowerCase();
        if (inputName.endsWith(".class")) {
            Files.write(output, remapClass(Files.readAllBytes(input), mappings), StandardOpenOption.CREATE_NEW);
            return;
        }
        try (ZipFile archive = new ZipFile(input.toFile()); ZipOutputStream target = new ZipOutputStream(Files.newOutputStream(output, StandardOpenOption.CREATE_NEW))) {
            var entries = archive.entries();
            while (entries.hasMoreElements()) {
                ZipEntry sourceEntry = entries.nextElement();
                String targetName = oldClassEntry != null && sourceEntry.getName().equals(oldClassEntry + ".class") ? newClassEntry + ".class" : sourceEntry.getName();
                target.putNextEntry(new ZipEntry(targetName));
                if (!sourceEntry.isDirectory()) {
                    try (var stream = archive.getInputStream(sourceEntry)) {
                        byte[] content = readBounded(stream);
                        if (sourceEntry.getName().endsWith(".class")) {
                            content = remapClass(content, mappings);
                        }
                        target.write(content);
                    }
                }
                target.closeEntry();
            }
        }
    }

    private static JsonObject mappingData(String kind, String before, String after, Path output) throws IOException {
        JsonObject data = new JsonObject();
        data.addProperty("mapping_kind", kind);
        data.addProperty("name_before", before);
        data.addProperty("name_after", after);
        data.addProperty("output_path", output.toString());
        data.addProperty("output_sha256", sha256(output));
        return data;
    }

    private static byte[] remapClass(byte[] input, Map<String, String> mappings) {
        ClassReader reader = new ClassReader(input);
        ClassWriter writer = new ClassWriter(reader, 0);
        SimpleRemapper remapper = new SimpleRemapper(mappings) {
            @Override
            public String mapFieldName(String owner, String name, String descriptor) {
                String mapped = mappings.get("field:" + owner + "." + name + ":" + descriptor);
                return mapped == null ? super.mapFieldName(owner, name, descriptor) : mapped;
            }
        };
        reader.accept(new ClassRemapper(writer, remapper), 0);
        return writer.toByteArray();
    }

    private static Workspace buildWorkspace(Map<String, JvmClassInfo> classes) {
        BasicJvmClassBundle bundle = new BasicJvmClassBundle();
        classes.values().forEach(bundle::initialPut);
        WorkspaceResource resource = new WorkspaceResourceBuilder().withJvmClassBundle(bundle).build();
        return new BasicWorkspace(resource, java.util.List.of(), false);
    }

    private static Map<String, JvmClassInfo> loadClasses(Path input) throws IOException {
        long size = Files.size(input);
        if (size <= 0 || size > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("input size is outside the worker limit");
        }
        Map<String, JvmClassInfo> classes = new LinkedHashMap<>();
        String name = input.getFileName().toString().toLowerCase();
        if (name.endsWith(".class")) {
            addClass(classes, Files.readAllBytes(input));
        } else {
            try (ZipFile archive = new ZipFile(input.toFile())) {
                var entries = archive.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                        continue;
                    }
                    if (entry.getSize() > MAX_INPUT_BYTES || classes.size() >= MAX_CLASSES) {
                        throw new IllegalArgumentException("archive exceeds the worker class limit");
                    }
                    try (var stream = archive.getInputStream(entry)) {
                        addClass(classes, readBounded(stream));
                    }
                }
            }
        }
        if (classes.isEmpty()) {
            throw new IllegalArgumentException("input contains no readable JVM classes");
        }
        return classes;
    }

    private static byte[] readBounded(java.io.InputStream stream) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[16_384];
        int total = 0;
        while (true) {
            int count = stream.read(buffer);
            if (count < 0) {
                return output.toByteArray();
            }
            total += count;
            if (total > MAX_INPUT_BYTES) {
                throw new IllegalArgumentException("archive entry exceeds the worker size limit");
            }
            output.write(buffer, 0, count);
        }
    }

    private static void addClass(Map<String, JvmClassInfo> classes, byte[] bytecode) {
        if (bytecode.length == 0 || bytecode.length > MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("class is outside the worker size limit");
        }
        JvmClassInfo info = new JvmClassInfoBuilder(bytecode).build();
        classes.putIfAbsent(info.getName(), info);
    }

    private static Path requireWorkspaceInput(JsonObject request) throws IOException {
        return requireWorkspaceInput(request, "path");
    }

    private static Path requireWorkspaceInput(JsonObject request, String key) throws IOException {
        String raw = requireString(request, key, 16_384);
        if (raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("path is malformed");
        }
        Path root = Path.of(requireEnvironmentPath("REA_FORGE_JAVA_WORKSPACE"));
        Path candidate = Path.of(raw).toAbsolutePath().normalize();
        if (!candidate.startsWith(root) || !Files.isRegularFile(candidate)) {
            throw new IllegalArgumentException("path is outside the workspace");
        }
        String filename = candidate.getFileName().toString().toLowerCase();
        if (!(filename.endsWith(".class") || filename.endsWith(".jar") || filename.endsWith(".war"))) {
            throw new IllegalArgumentException("input type is not allowed");
        }
        return candidate;
    }

    private static Path requireWorkspaceJavaSource(JsonObject request) throws IOException {
        String raw = requireString(request, "source_path", 16_384);
        return requireWorkspaceJavaSource(raw);
    }

    private static Path requireWorkspaceJavaSource(String raw) throws IOException {
        if (raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("source path is malformed");
        }
        Path root = Path.of(requireEnvironmentPath("REA_FORGE_JAVA_WORKSPACE"));
        Path candidate = Path.of(raw).toAbsolutePath().normalize();
        if (!candidate.startsWith(root) || !Files.isRegularFile(candidate) || Files.size(candidate) > 512 * 1024 || !candidate.getFileName().toString().toLowerCase().endsWith(".java")) {
            throw new IllegalArgumentException("source is outside the bounded Java workspace policy");
        }
        return candidate;
    }

    private static List<Path> requireWorkspaceJavaSources(JsonObject request) throws IOException {
        JsonElement element = request.get("source_paths");
        if (element == null || !element.isJsonArray() || element.getAsJsonArray().size() < 2 || element.getAsJsonArray().size() > MAX_COMPILE_SET_SOURCES) {
            throw new IllegalArgumentException("multi-source paths are outside the worker bound");
        }
        List<Path> result = new ArrayList<>();
        Set<Path> distinct = new HashSet<>();
        long totalSize = 0;
        for (JsonElement item : element.getAsJsonArray()) {
            if (!item.isJsonPrimitive() || !item.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException("multi-source path is malformed");
            }
            Path source = requireWorkspaceJavaSource(item.getAsString());
            if (!distinct.add(source)) {
                throw new IllegalArgumentException("multi-source paths must be distinct");
            }
            totalSize += Files.size(source);
            if (totalSize > MAX_COMPILE_SET_BYTES) {
                throw new IllegalArgumentException("multi-source files exceed the worker limit");
            }
            result.add(source);
        }
        return result;
    }

    private static List<Path> requireWorkspaceDependencyJars(JsonObject request) throws IOException {
        JsonElement element = request.get("dependency_paths");
        if (element == null) {
            return List.of();
        }
        if (!element.isJsonArray() || element.getAsJsonArray().size() > MAX_DEPENDENCY_JARS) {
            throw new IllegalArgumentException("dependency JAR paths are outside the worker bound");
        }
        Path root = Path.of(requireEnvironmentPath("REA_FORGE_JAVA_WORKSPACE"));
        List<Path> result = new ArrayList<>();
        Set<Path> distinct = new HashSet<>();
        long totalSize = 0;
        for (JsonElement item : element.getAsJsonArray()) {
            if (!item.isJsonPrimitive() || !item.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException("dependency JAR path is malformed");
            }
            String raw = item.getAsString();
            if (raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("dependency JAR path is malformed");
            }
            Path candidate = Path.of(raw).toAbsolutePath().normalize();
            if (!candidate.startsWith(root) || !Files.isRegularFile(candidate) || !candidate.getFileName().toString().toLowerCase().endsWith(".jar") || Files.size(candidate) > MAX_DEPENDENCY_JAR_BYTES || !distinct.add(candidate)) {
                throw new IllegalArgumentException("dependency JAR is outside the bounded workspace policy");
            }
            totalSize += Files.size(candidate);
            if (totalSize > MAX_DEPENDENCY_TOTAL_BYTES) {
                throw new IllegalArgumentException("dependency JARs exceed the worker limit");
            }
            result.add(candidate);
        }
        return result;
    }

    private static Path requireWorkspaceAssemblySource(JsonObject request) throws IOException {
        String raw = requireString(request, "assembly_path", 1_024);
        if (raw.indexOf('\n') >= 0 || raw.indexOf('\r') >= 0 || raw.indexOf('\0') >= 0 || !raw.toLowerCase().endsWith(".jasm")) {
            throw new IllegalArgumentException("assembly path is malformed");
        }
        Path root = Path.of(requireEnvironmentPath("REA_FORGE_JAVA_WORKSPACE"));
        Path candidate = Path.of(raw).toAbsolutePath().normalize();
        if (!candidate.startsWith(root) || !Files.isRegularFile(candidate) || Files.size(candidate) > 512 * 1024) {
            throw new IllegalArgumentException("assembly path is not a bounded workspace source");
        }
        return candidate;
    }

    private static Path requireWorkspaceOutput(JsonObject request) throws IOException {
        String raw = requireString(request, "output_path", 16_384);
        Path root = Path.of(requireEnvironmentPath("REA_FORGE_JAVA_WORKSPACE"));
        Path candidate = Path.of(raw).toAbsolutePath().normalize();
        if (!candidate.startsWith(root) || Files.exists(candidate) || !Files.isDirectory(candidate.getParent())) {
            throw new IllegalArgumentException("output path is not a new workspace child");
        }
        String filename = candidate.getFileName().toString().toLowerCase();
        if (!(filename.endsWith(".class") || filename.endsWith(".jar") || filename.endsWith(".war"))) {
            throw new IllegalArgumentException("output type is not allowed");
        }
        return candidate;
    }

    private static String requireClassName(JsonObject request) {
        return requireClassName(request, "class_name");
    }

    private static String requireClassName(JsonObject request, String key) {
        String name = requireString(request, key, 512).replace('.', '/');
        if (!name.matches("[A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)*")) {
            throw new IllegalArgumentException("class name is malformed");
        }
        return name;
    }

    private static String requireMemberName(JsonObject request, String key) {
        String name = requireString(request, key, 512);
        if (!name.matches("[A-Za-z_$][A-Za-z0-9_$]*")) {
            throw new IllegalArgumentException("member name is malformed");
        }
        return name;
    }

    private static String requireMethodDescriptor(JsonObject request) {
        String descriptor = requireString(request, "descriptor", 1_024);
        try {
            org.objectweb.asm.Type.getMethodType(descriptor);
            return descriptor;
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("method descriptor is malformed");
        }
    }

    private static String requireFieldDescriptor(JsonObject request) {
        String descriptor = requireString(request, "descriptor", 1_024);
        try {
            if (org.objectweb.asm.Type.getType(descriptor).getSort() == org.objectweb.asm.Type.METHOD) {
                throw new IllegalArgumentException("field descriptor is malformed");
            }
            return descriptor;
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("field descriptor is malformed");
        }
    }

    private static String requireSearchQuery(JsonObject request) {
        String query = requireString(request, "query", 256);
        if (query.indexOf('\n') >= 0 || query.indexOf('\r') >= 0 || query.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("search query is malformed");
        }
        return query;
    }

    private static String requireSearchKind(JsonObject request) {
        String kind = requireString(request, "kind", 32);
        if (!("any".equals(kind) || "class_name".equals(kind) || "member_name".equals(kind) || "string_constant".equals(kind) || "reference".equals(kind))) {
            throw new IllegalArgumentException("search kind is not allowed");
        }
        return kind;
    }

    private static String requireTransformer(JsonObject request) {
        String transformer = requireString(request, "transformer", 64);
        if (!("dead_code_remove".equals(transformer) || "duplicate_annotation_remove".equals(transformer))) {
            throw new IllegalArgumentException("transformer is not allowed");
        }
        return transformer;
    }

    private static int requireJavaRelease(JsonObject request) {
        JsonElement element = request.get("release");
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException("Java release is missing");
        }
        int release = element.getAsInt();
        if (!(release == 8 || release == 11 || release == 17 || release == 21 || release == 25)) {
            throw new IllegalArgumentException("Java release is not allowed");
        }
        return release;
    }

    private static String sha256(Path path) throws IOException {
        return sha256(Files.readAllBytes(path));
    }

    private static String sha256(byte[] content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                builder.append(String.format("%02x", value));
            }
            return builder.toString();
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String requireEngine(JsonObject request) {
        String engine = requireString(request, "engine", 32);
        if (!"cfr".equals(engine) && !"vineflower".equals(engine)) {
            throw new IllegalArgumentException("engine is not allowed");
        }
        return engine;
    }

    private static String requireString(JsonObject request, String key, int maximumLength) {
        JsonElement element = request.get(key);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("request field is missing");
        }
        String value = element.getAsString();
        if (value.isEmpty() || value.length() > maximumLength) {
            throw new IllegalArgumentException("request field is outside bounds");
        }
        return value;
    }

    private static String requireEnvironmentPath(String name) {
        String value = System.getenv(name);
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("worker environment is incomplete");
        }
        return value;
    }

    private static final class MemoryJavaSource extends SimpleJavaFileObject {
        private final String source;

        private MemoryJavaSource(String binaryName, String source) {
            super(URI.create("string:///" + binaryName.replace('.', '/') + Kind.SOURCE.extension), Kind.SOURCE);
            this.source = source;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
        }
    }

    private static final class MemoryClassFile extends SimpleJavaFileObject {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();

        private MemoryClassFile(String binaryName) {
            super(URI.create("mem:///" + binaryName.replace('.', '/') + Kind.CLASS.extension), Kind.CLASS);
        }

        @Override
        public OutputStream openOutputStream() {
            return output;
        }

        private byte[] bytes() {
            return output.toByteArray();
        }
    }

    private static final class MemoryJavaFileManager extends ForwardingJavaFileManager<StandardJavaFileManager> {
        private final Map<String, MemoryClassFile> classes = new LinkedHashMap<>();

        private MemoryJavaFileManager(StandardJavaFileManager manager) {
            super(manager);
        }

        @Override
        public JavaFileObject getJavaFileForOutput(JavaFileManager.Location location, String className, JavaFileObject.Kind kind, FileObject sibling) throws IOException {
            if (kind != JavaFileObject.Kind.CLASS || classes.containsKey(className)) {
                throw new IOException("compiler emitted a disallowed output");
            }
            MemoryClassFile target = new MemoryClassFile(className);
            classes.put(className, target);
            return target;
        }

        private int classCount() {
            return classes.size();
        }

        private boolean hasClass(String binaryName) {
            return classes.containsKey(binaryName);
        }

        private byte[] classBytes(String binaryName) {
            MemoryClassFile file = classes.get(binaryName);
            if (file == null) {
                throw new IllegalArgumentException("compiled class is missing");
            }
            return file.bytes();
        }

        private Map<String, byte[]> compiledClasses() {
            Map<String, byte[]> result = new LinkedHashMap<>();
            classes.forEach((name, file) -> result.put(name, file.bytes()));
            return result;
        }
    }

    private static void succeed(JsonObject data) {
        JsonObject response = new JsonObject();
        response.addProperty("ok", true);
        response.add("data", data);
        System.out.print(GSON.toJson(response));
    }

    private static void fail(String code) {
        JsonObject response = new JsonObject();
        response.addProperty("ok", false);
        response.addProperty("error", code);
        System.out.print(GSON.toJson(response));
    }
}
