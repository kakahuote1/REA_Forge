package forge.bcv;

import com.strobel.assembler.metadata.Buffer;
import com.strobel.assembler.metadata.ITypeLoader;
import com.strobel.decompiler.Decompiler;
import com.strobel.decompiler.DecompilerSettings;
import com.strobel.decompiler.PlainTextOutput;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import org.jd.core.v1.ClassFileToJavaSourceDecompiler;
import org.jd.core.v1.api.loader.Loader;
import org.jd.core.v1.api.loader.LoaderException;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.util.ASMifier;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceClassVisitor;
import the.bytecode.club.bytecodeviewer.decompilers.jdgui.CommonPreferences;
import the.bytecode.club.bytecodeviewer.decompilers.jdgui.PlainTextPrinter;

/**
 * Fixed, headless entry point for audited Bytecode Viewer v2.12 library APIs.
 * It deliberately never loads BytecodeViewer.main or any plugin, script, GUI,
 * network, update, compile, assembler, or process-launch path.
 */
public final class Worker {
    private static final long MAX_INPUT_BYTES = 8L * 1024L * 1024L;

    private Worker() {
    }

    public static void main(String[] args) {
        try {
            Map<String, String> values = parse(args);
            Path input = absoluteExistingFile(values.get("--input"));
            Path output = absoluteNewOutput(values.get("--output"));
            String requestedName = validInternalName(values.get("--class-name"));
            byte[] data = Files.readAllBytes(input);
            if (data.length == 0 || data.length > MAX_INPUT_BYTES) {
                throw new IllegalArgumentException("input_size_invalid");
            }
            ClassReader reader = new ClassReader(data);
            if (!requestedName.equals(reader.getClassName())) {
                throw new IllegalArgumentException("class_identity_invalid");
            }
            Path classRoot = null;
            if (values.containsKey("--class-root")) {
                classRoot = Path.of(values.get("--class-root")).toRealPath();
                if (!input.toRealPath().equals(classRoot.resolve(requestedName + ".class").normalize())) {
                    throw new IllegalArgumentException("class_root_identity_invalid");
                }
            }
            String rendered = render(values.get("--engine"), requestedName, data, reader, classRoot);
            if (rendered.isEmpty() || rendered.getBytes(StandardCharsets.UTF_8).length > 512 * 1024) {
                throw new IllegalArgumentException("output_size_invalid");
            }
            Files.createDirectories(output.getParent());
            Files.writeString(output, rendered, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (Throwable failure) {
            System.err.println("rea_forge_bcv_worker_rejected_request");
            // Bounded diagnostic frames, without exception messages containing
            // arbitrary input text. Keep the public MCP error stable.
            System.err.println("exception=" + failure.getClass().getName());
            StackTraceElement[] frames = failure.getStackTrace();
            for (int index = 0; index < Math.min(frames.length, 12); index++) {
                System.err.println("at " + frames[index]);
            }
            System.exit(2);
        }
    }

    private static Map<String, String> parse(String[] args) {
        if (args.length != 8 && args.length != 10) {
            throw new IllegalArgumentException("argument_count_invalid");
        }
        Map<String, String> values = new HashMap<>();
        for (int index = 0; index < args.length; index += 2) {
            String key = args[index];
            String value = args[index + 1];
            if (!"--engine".equals(key) && !"--input".equals(key) && !"--output".equals(key) && !"--class-name".equals(key) && !"--class-root".equals(key)
                    || value.isEmpty() || values.put(key, value) != null) {
                throw new IllegalArgumentException("argument_invalid");
            }
        }
        if (!values.keySet().containsAll(java.util.Set.of("--engine", "--input", "--output", "--class-name"))) {
            throw new IllegalArgumentException("argument_invalid");
        }
        return values;
    }

    private static Path absoluteExistingFile(String raw) throws IOException {
        Path path = Path.of(raw).toAbsolutePath().normalize();
        if (!path.isAbsolute() || !Files.isRegularFile(path) || Files.isSymbolicLink(path)) {
            throw new IllegalArgumentException("input_path_invalid");
        }
        return path;
    }

    private static Path absoluteNewOutput(String raw) {
        Path path = Path.of(raw).toAbsolutePath().normalize();
        if (!path.isAbsolute() || Files.exists(path) || path.getParent() == null) {
            throw new IllegalArgumentException("output_path_invalid");
        }
        return path;
    }

    private static String validInternalName(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > 256 || raw.startsWith("/") || raw.endsWith("/") || raw.contains("..")) {
            throw new IllegalArgumentException("class_name_invalid");
        }
        for (int index = 0; index < raw.length(); index++) {
            char value = raw.charAt(index);
            if (!(Character.isLetterOrDigit(value) || value == '_' || value == '$' || value == '/')) {
                throw new IllegalArgumentException("class_name_invalid");
            }
        }
        return raw;
    }

    private static String render(String engine, String internalName, byte[] data, ClassReader reader, Path classRoot) throws Exception {
        ClassNode node = new ClassNode();
        reader.accept(node, 0);
        OneClassLoader loader = new OneClassLoader(internalName, data, classRoot);
        return switch (engine) {
            case "procyon" -> procyon(internalName, loader);
            case "jd_core" -> jdCore(internalName, loader);
            case "asm_textifier" -> asmTextifier(node);
            case "asmifier" -> asmifier(node);
            default -> throw new IllegalArgumentException("engine_invalid");
        };
    }

    private static String procyon(String internalName, OneClassLoader loader) throws IOException {
        DecompilerSettings settings = DecompilerSettings.javaDefaults();
        settings.setTypeLoader(loader);
        settings.setShowSyntheticMembers(true);
        settings.setUnicodeOutputEnabled(true);
        StringWriter result = new StringWriter();
        Decompiler.decompile(internalName, new PlainTextOutput(result), settings);
        return result.toString();
    }

    private static String jdCore(String internalName, OneClassLoader loader) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        CommonPreferences preferences = new CommonPreferences(false, false, true, true, false, false);
        try (PrintStream stream = new PrintStream(bytes, true, StandardCharsets.UTF_8);
             PlainTextPrinter printer = new PlainTextPrinter(preferences, stream)) {
            new ClassFileToJavaSourceDecompiler().decompile(loader, printer, internalName, preferences.getPreferences());
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static String asmTextifier(ClassNode node) {
        StringWriter result = new StringWriter();
        node.accept(new TraceClassVisitor(null, new Textifier(), new PrintStreamWriter(result)));
        return result.toString();
    }

    private static String asmifier(ClassNode node) {
        StringWriter result = new StringWriter();
        node.accept(new TraceClassVisitor(null, new ASMifier(), new PrintStreamWriter(result)));
        return result.toString();
    }

    private static final class OneClassLoader implements Loader, ITypeLoader {
        private final String internalName;
        private final byte[] data;
        private final Path root;
        private final Map<String, byte[]> cache = new HashMap<>();
        private long loadedBytes;

        private OneClassLoader(String internalName, byte[] data, Path root) {
            this.internalName = internalName;
            this.data = data.clone();
            this.root = root;
            this.loadedBytes = data.length;
            this.cache.put(internalName, this.data);
        }

        @Override
        public boolean canLoad(String name) {
            try {
                return cache.containsKey(name) || classPath(name) != null;
            } catch (IOException | IllegalArgumentException failure) {
                return false;
            }
        }

        private Path classPath(String name) throws IOException {
            validInternalName(name);
            if (root == null) return null;
            Path candidate = root.resolve(name + ".class").normalize();
            if (!candidate.startsWith(root) || !Files.isRegularFile(candidate)) return null;
            Path real = candidate.toRealPath();
            if (!real.startsWith(root) || Files.isSymbolicLink(candidate)) {
                throw new IllegalArgumentException("class_context_path_invalid");
            }
            return real;
        }

        @Override
        public byte[] load(String name) throws LoaderException {
            byte[] cached = cache.get(name);
            if (cached != null) return cached.clone();
            try {
                Path path = classPath(name);
                // Missing optional dependencies use JD-Core's null contract.
                if (path == null) return null;
                long size = Files.size(path);
                if (size <= 0 || size > MAX_INPUT_BYTES || loadedBytes + size > 32L * 1024L * 1024L || cache.size() >= 4096) {
                    throw new IllegalArgumentException("class_context_size_invalid");
                }
                byte[] bytes = Files.readAllBytes(path);
                if (bytes.length != size || !new ClassReader(bytes).getClassName().equals(name)) {
                    throw new IllegalArgumentException("class_context_identity_invalid");
                }
                loadedBytes += size;
                cache.put(name, bytes);
                return bytes.clone();
            } catch (IOException | IllegalArgumentException failure) {
                throw new LoaderException("class_context_rejected");
            }
        }

        @Override
        public boolean tryLoadType(String name, Buffer buffer) {
            try {
                byte[] bytes = load(name);
                if (bytes == null) return false;
                buffer.reset(bytes.length);
                buffer.putByteArray(bytes, 0, bytes.length);
                buffer.position(0);
                return true;
            } catch (LoaderException failure) {
                throw new IllegalArgumentException("class_context_rejected", failure);
            }
        }
    }

    private static final class PrintStreamWriter extends PrintWriter {
        private PrintStreamWriter(StringWriter writer) {
            super(writer);
        }
    }
}
