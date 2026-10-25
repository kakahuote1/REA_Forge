import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import me.yricky.oh.abcd.AbcBuf;
import me.yricky.oh.abcd.cfm.*;
import me.yricky.oh.abcd.code.Code;
import me.yricky.oh.abcd.isa.*;
import me.yricky.oh.abcd.isa.util.*;
import me.yricky.oh.abcd.decompiler.ToJs;
import me.yricky.oh.common.MiscKt;

/** Fixed headless adapter over the locally hash-pinned abcde library. */
public final class AbcdeReader {
    private static long outputBytes;
    private static int rows;
    private static Map<String,Object> object(Object... pairs) {
        Map<String,Object> result = new LinkedHashMap<>();
        for (int i=0; i<pairs.length; i+=2) result.put((String)pairs[i], pairs[i+1]);
        return result;
    }
    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?,?>) {
            List<String> parts = new ArrayList<>();
            for (Map.Entry<?,?> e: ((Map<?,?>)value).entrySet()) parts.add(json(e.getKey())+":"+json(e.getValue()));
            return "{"+String.join(",",parts)+"}";
        }
        if (value instanceof Iterable<?>) {
            List<String> parts = new ArrayList<>();
            for (Object item: (Iterable<?>)value) parts.add(json(item));
            return "["+String.join(",",parts)+"]";
        }
        StringBuilder s = new StringBuilder("\"");
        for (char c: value.toString().toCharArray()) {
            if (c=='"' || c=='\\') s.append('\\').append(c);
            else if (c<32 || Character.isSurrogate(c)) s.append(String.format("\\u%04x",(int)c));
            else s.append(c);
        }
        return s.append('"').toString();
    }
    private static void row(OutputStream out, Map<String,Object> data) throws IOException {
        byte[] bytes = (json(data)+"\n").getBytes(StandardCharsets.UTF_8);
        outputBytes += bytes.length;
        if (++rows > 500000 || outputBytes > 128L*1024*1024 || bytes.length > 1024*1024)
            throw new IOException("output bound exceeded; partial output is not a result");
        out.write(bytes);
    }
    private static Map<String,Object> methodInfo(AbcMethod method) {
        Code code = method.getCodeItem();
        return object("kind","method","class",method.getClazz().getName(),"name",method.getName(),
            "method_offset",method.getOffset(),"has_code",code!=null,
            "code_size",code==null?0:code.getCodeSize(),"try_count",code==null?0:code.getTriesSize(),
            "arguments",code==null?0:code.getNumArgs(),"registers",code==null?0:code.getNumVRegs());
    }
    public static void main(String[] args) throws Throwable {
        if (args.length!=4 || !Set.of("methods","disassemble","decompile").contains(args[0]) || !args[3].matches("[0-9]{1,10}"))
            throw new IllegalArgumentException("fixed action/input/new-output/decimal-offset required");
        Path input=Path.of(args[1]), output=Path.of(args[2]);
        long size=Files.size(input), selected=Long.parseLong(args[3]);
        if (size<60 || size>64000000 || selected>Integer.MAX_VALUE || Files.exists(output)) throw new IllegalArgumentException("invalid input/output");
        byte[] bytes=Files.readAllBytes(input);
        ByteBuffer buffer=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        if (!Arrays.equals(Arrays.copyOf(bytes,8),new byte[]{80,65,78,68,65,0,0,0}) || buffer.getInt(16)!=size)
            throw new IllegalArgumentException("invalid Panda header");
        AbcBuf abc=new AbcBuf(input.toString(), MiscKt.wrapAsLEByteBuf(buffer.asReadOnlyBuffer()));
        AbcMethod target=null;
        try (OutputStream out=new BufferedOutputStream(Files.newOutputStream(output,StandardOpenOption.CREATE_NEW))) {
            if (args[0].equals("methods")) {
                if (selected!=0) throw new IllegalArgumentException("methods requires offset zero");
                for (ClassItem item: abc.getClasses().values()) {
                    row(out,object("kind","class","name",item.getName(),"class_offset",item.getOffset(),"foreign",!(item instanceof AbcClass)));
                    if (!(item instanceof AbcClass)) continue;
                    AbcClass cls=(AbcClass)item;
                    for (AbcField field: cls.getFields()) row(out,object("kind","field","class",cls.getName(),"name",field.getName(),"field_offset",field.getOffset()));
                    for (AbcMethod method: cls.getMethods()) row(out,methodInfo(method));
                }
            } else {
                for (ClassItem item: abc.getClasses().values()) {
                    if (item instanceof AbcClass) for (AbcMethod method: ((AbcClass)item).getMethods()) {
                        if (method.getOffset()==selected) target=method;
                    }
                }
                if (target==null || target.getCodeItem()==null) throw new IllegalArgumentException("method not found or has no code");
                Code code=target.getCodeItem();
                row(out,methodInfo(target));
                if (args[0].equals("decompile")) {
                    if (code.getTriesSize()!=0) throw new UnsupportedOperationException("experimental decompiler does not support try/catch");
                    row(out,object("kind","experimental_js","semantics_verified",false,"source",new ToJs(code.getAsm()).toJS(false)));
                } else {
                    for (Asm.AsmItem item: code.getAsm().getList()) {
                        List<String> operands=new ArrayList<>(), strings=new ArrayList<>();
                        List<Object> methods=new ArrayList<>();
                        for (int i=0;i<item.getOpUnits().size();i++) {
                            InstDisAsmParser.ParsedArg arg=BaseInstParser.INSTANCE.parseArg(item,i);
                            if(arg!=null) operands.add(arg.getText());
                        }
                        Iterator<AbcMethod> mi=AsmKt.getCalledMethods(item).iterator();
                        while(mi.hasNext()) { AbcMethod m=mi.next(); methods.add(object("method_offset",m.getOffset(),"class",m.getClazz().getName(),"name",m.getName())); }
                        Iterator<String> si=AsmKt.getCalledStrings(item).iterator();
                        while(si.hasNext()) strings.add(si.next());
                        row(out,object("kind","instruction","code_offset",item.getCodeOffset(),"next_offset",item.getNextOffset(),
                            "mnemonic",item.getIns().getAsmName(),"operands",operands,"referenced_methods",methods,"referenced_strings",strings,
                            "reference_semantics","encoded references including definitions/literals; not a proven call graph"));
                    }
                }
            }
        }
        System.out.println(json(object("ok",true,"rows",rows,"output_bytes",outputBytes,"action",args[0])));
    }
}
