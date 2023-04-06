
/*
 * Created on Mon Nov 02 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

package com.oracle.svm.hosted.c.codegen;

import static com.oracle.svm.core.SubstrateUtil.mangleName;
import static com.oracle.svm.core.util.VMError.shouldNotReachHere;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.invoke.MethodType;
import java.lang.reflect.AnnotatedType;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.graalvm.collections.Pair;
import org.graalvm.compiler.code.CompilationResult;
import org.graalvm.compiler.core.common.CompressEncoding;
import org.graalvm.compiler.core.common.NumUtil;
import org.graalvm.compiler.debug.DebugContext;
import org.graalvm.compiler.debug.Indent;
import org.graalvm.compiler.serviceprovider.BufferUtil;
import org.graalvm.nativeimage.ImageSingletons;
import org.graalvm.nativeimage.SecurityInfo;
import org.graalvm.nativeimage.c.function.CFunctionPointer;

import com.oracle.graal.pointsto.meta.AnalysisMethod;
import com.oracle.graal.pointsto.meta.AnalysisType;
import com.oracle.objectfile.BasicProgbitsSectionImpl;
import com.oracle.objectfile.BuildDependency;
import com.oracle.objectfile.LayoutDecision;
import com.oracle.objectfile.LayoutDecisionMap;
import com.oracle.objectfile.ObjectFile;
import com.oracle.objectfile.ObjectFile.Element;
import com.oracle.objectfile.ObjectFile.ProgbitsSectionImpl;
import com.oracle.objectfile.ObjectFile.RelocationKind;
import com.oracle.objectfile.ObjectFile.Section;
import com.oracle.objectfile.SectionName;
import com.oracle.objectfile.debuginfo.DebugInfoProvider;
import com.oracle.objectfile.macho.MachOObjectFile;
import com.oracle.svm.core.FrameAccess;
import com.oracle.svm.core.Isolates;
import com.oracle.svm.core.SubstrateOptions;
import com.oracle.svm.core.SubstrateUtil;
import com.oracle.svm.core.c.CConst;
import com.oracle.svm.core.c.CGlobalDataImpl;
import com.oracle.svm.core.c.CHeader;
import com.oracle.svm.core.c.CHeader.Header;
import com.oracle.svm.core.c.CTypedef;
import com.oracle.svm.core.c.CUnsigned;
import com.oracle.svm.core.c.function.CEntryPointOptions.Publish;
import com.oracle.svm.core.c.function.GraalIsolateHeader;
import com.oracle.svm.core.config.ConfigurationValues;
import com.oracle.svm.core.graal.code.CGlobalDataInfo;
import com.oracle.svm.core.graal.code.CGlobalDataReference;
import com.oracle.svm.core.image.ImageHeapLayoutInfo;
import com.oracle.svm.core.image.ImageHeapLayouter;
import com.oracle.svm.core.image.ImageHeapPartition;
import com.oracle.svm.core.meta.SubstrateObjectConstant;
import com.oracle.svm.core.option.HostedOptionValues;
import com.oracle.svm.core.util.UserError;
import com.oracle.svm.hosted.NativeImageOptions;
import com.oracle.svm.hosted.c.CGlobalDataFeature;
import com.oracle.svm.hosted.c.GraalAccess;
import com.oracle.svm.hosted.c.NativeLibraries;
import com.oracle.svm.hosted.c.codegen.CSourceCodeWriter;
import com.oracle.svm.hosted.c.codegen.QueryCodeWriter;
import com.oracle.svm.hosted.code.CEntryPointCallStubMethod;
import com.oracle.svm.hosted.code.CEntryPointCallStubSupport;
import com.oracle.svm.hosted.code.CEntryPointData;
//import com.oracle.svm.hosted.image.NativeImageHeap.ObjectInfo;
//import com.oracle.svm.hosted.image.RelocatableBuffer.Info;
import com.oracle.svm.hosted.image.sources.SourceManager;
import com.oracle.svm.hosted.meta.HostedMetaAccess;
import com.oracle.svm.hosted.meta.HostedMethod;
import com.oracle.svm.hosted.meta.HostedUniverse;
import com.oracle.svm.hosted.meta.MethodPointer;
import com.oracle.svm.util.ReflectionUtil;
import com.oracle.svm.util.ReflectionUtil.ReflectionUtilError;

import jdk.vm.ci.aarch64.AArch64;
import jdk.vm.ci.amd64.AMD64;
import jdk.vm.ci.code.Architecture;
import jdk.vm.ci.code.site.ConstantReference;
import jdk.vm.ci.code.site.DataSectionReference;
import jdk.vm.ci.meta.ResolvedJavaMethod;
import jdk.vm.ci.meta.ResolvedJavaMethod.Parameter;
import jdk.vm.ci.meta.ResolvedJavaType;

import jdk.vm.ci.meta.JavaKind;
import jdk.vm.ci.meta.MetaAccessProvider;

//TODO: remove useless imports

/** Used to specify the type of file/routine we are writing */
enum SGXHeader {
    /**
     * Prefixed with ecall_ or ocall_. This convention should be followed by the
     * java programmer when calling a corresponding transition function.
     */
    PROXY,
    /**
     * Prefixed with graalsgx_ocall: real ocall definitions out of enclave which
     * invoke unsecure entrypoints
     */
    OCALL,
    /**
     * Prefixed with graalsgx_ecall: real ocall definitions in enclave which invoke
     * secure entrypoints
     */
    ECALL
}

/**
 * PYuhala: SGX proxy routine generator. This tool generates the necessary proxy
 * routines, EDL files, ecalls and ocalls necessary to "glue" the secure and
 * unsecure runtimes. The files generated here will be copied to the sgx module
 * which will compile them and link appropriately to the corresponding runtime.
 * The generated file will be included in the appropriate "parent" file in the
 * sgx module. These files are not standalone; the useful header files required
 * by these will be included in those parent files.
 */

public class SGXProxyGenerator {

    private Path tmpDir;
    public static final String HPP_FILE_EXTENSION = ".hpp";
    public static final String EDL_FILE_EXTENSION = ".edl";
    /** Name of global enclave id variable in sgx module */
    public static final String GLOBAL_EID = "global_eid";
    /** Enclave isolate name; ecall threads are attached here by default */
    public static final String ENC_ISO = "global_enc_iso";
    /** App isolate name; ocall threads are attached here by default */
    public static final String APP_ISO = "global_app_iso";
    /** This instruction prints debug information if it is set in the sgx module */
    public static final String DEBUG_INFO = "GRAAL_SGX_INFO();";
    /** CCharPointer type */
    public static final String ccharpointer = "org.graalvm.nativeimage.c.type.CCharPointer";
    /** Space */
    public static final String space = " ";
    /** Comma */
    public static final String comma = ",";

    public static final String GRAAL_ISO_TYPE_CAST = "(graal_isolatethread_t*)";

    /** C NULL pointer */
    public static final String C_NULL = "NULL";

    /**
     * Isolate to be used as execution context for transition routine. It is either
     * generated or given the value of the default isolate thread for that runtime.
     */
    public static String TEMP_ISOLATE;
    /** Destroy temporary isolate thread after transition routine returns */
    public static String DESTROY_TEMP_ISOLATE;

    private NativeLibraries nativeLibs;
    private HostedMetaAccess hMetaAccess;
    private ClassLoader imageClassLoader;
    /**
     * For secure runtime, this defines the ecalls that invoke the entrypoint
     * methods in the enclave. For unsecure runtime, it defines the ocalls that
     * invoke the entrypoint methods in the untrusted rt
     */
    private String sourceFileName;

    /**
     * The edl file contains edl definitions for ecalls or ocalls for secure and
     * unsecure image respectively
     */
    private String edlFileName;

    /**
     * Contains the definitions of the corresponding proxies invoked in the java
     * code via graal's API. i.e the native methods imported. These proxies will
     * invoke the corresponding ecalls/ocalls routines which do the enclave
     * transition
     */
    private String proxyFileName;

    /** Indicates the security family of the image doing this proxy generations */
    private boolean isSecure;

    /** Generic comment added to the top of all generated files */
    private String headerComment = "/* Generated by GraalVM SGXProxyGenerator. */ ";

    public SGXProxyGenerator(boolean isSecure, NativeLibraries nLibs, HostedMetaAccess access, ClassLoader cLoader) {
        System.out.println("SGX Proxy Generator constructor --------------->");
        this.isSecure = isSecure;
        this.nativeLibs = nLibs;
        this.hMetaAccess = access;
        this.imageClassLoader = cLoader;

        if (this.tmpDir == null) {
            this.tmpDir = Paths.get(System.getProperty("java.io.tmpdir"));
        }
        if (isSecure) {
            sourceFileName = "graalsgx_ecalls" + HPP_FILE_EXTENSION;
            proxyFileName = "graalsgx_ecalls_proxy" + HPP_FILE_EXTENSION;
            edlFileName = "graalsgx_ecalls" + EDL_FILE_EXTENSION;
        } else {
            sourceFileName = "graalsgx_ocalls" + HPP_FILE_EXTENSION;
            proxyFileName = "graalsgx_ocalls_proxy" + HPP_FILE_EXTENSION;
            edlFileName = "graalsgx_ocalls" + EDL_FILE_EXTENSION;
        }

    }

    /**
     * PYuhala: Generate all necessary EDL and hpp files for the transition
     * routines. The file generation routines use different SGXProxyWriter objects
     * due to the nature the parent class is defined. I believe it was done that way
     * to simplify concurrency where multiple threads do generation at the same
     * time. Using one writer object in such scenarios will not work correctly.
     */
    public void generateProxies(List<HostedMethod> methods) {
        System.out.println("Generating sgx proxies: --------------> ");

        writeEdlFile(methods);

        if (this.isSecure) {
            writeEcallDefs(methods);
            writeEcallProxies(methods);
        } else {
            writeOcallDefs(methods);
            writeOcallProxies(methods);
        }

        copyGenFiles();
    }

    /**
     * Writes the SGX EDL file for ecalls or ocalls. For further understanding, see
     * SGX SDK for rules on writing EDL files
     */
    public void writeEdlFile(List<HostedMethod> methods) {
        SGXProxyWriter writer = new SGXProxyWriter(this.tmpDir);
        assert writer != null : "SGXProxyGenerator code writer null";

        String blockStart = this.isSecure ? "trusted {" : "untrusted {";
        String blockEnd = "};";

        writer.appendln(headerComment);
        writer.appendln();
        writer.appendln("enclave {");
        writer.indent();
        writer.indents().appendln(blockStart);
        writer.indent();
        methods.forEach(m -> writeEdlMethodHeader(m, writer));

        writer.outdent();
        writer.indents().appendln(blockEnd);
        writer.outdent();
        writer.appendln("};");

        /**
         * Write generated file to filesystem. CSourceCodeWriter.writeFile will
         * correctly resolve the path to edlFileName and write the corresponding file:
         * i.e /this.tmpDir/edlFileName
         */
        writer.writeFile(edlFileName);

    }

    /**
     * Writes the hpp file which contains ecall definitions. These definitions are
     * the real routines which run in the enclave and call the corresponding
     * entrypoint method. The generated file: graalsgx_in.hpp will be included in
     * the Enclave.cpp in the sgx module.
     */
    public void writeEcallDefs(List<HostedMethod> methods) {
        SGXProxyWriter writer = new SGXProxyWriter(this.tmpDir);
        assert writer != null : "SGXProxyGenerator code writer null";

        writer.appendln(headerComment);
        writer.appendln();
        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("extern \"C\" {");
        writer.appendln("#endif");
        writer.appendln();
        methods.forEach(m -> writeCMethodBody(m, writer, SGXHeader.ECALL));

        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("}");
        writer.appendln("#endif");

        /**
         * Write generated file to filesystem. CSourceCodeWriter.writeFile will
         * correctly resolve the path to edlFileName and write the corresponding file:
         * i.e /this.tmpDir/graalsgx_ecalls.hpp
         */
        writer.writeFile(sourceFileName);

    }

    /**
     * Writes the hpp file which contains the proxy methods which will call the
     * appropriate ecall routines. The generated file: ecall_proxy.hpp will be
     * included in App.cpp in the sgx module.
     */
    public void writeEcallProxies(List<HostedMethod> methods) {
        SGXProxyWriter writer = new SGXProxyWriter(this.tmpDir);
        assert writer != null : "SGXProxyGenerator code writer null";
        // SGXHeader.ECALL;

        writer.appendln(headerComment);
        writer.appendln();

        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("extern \"C\" {");
        writer.appendln("#endif");
        writer.appendln();
        methods.forEach(m -> writeCMethodBody(m, writer, SGXHeader.PROXY));

        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("}");
        writer.appendln("#endif");

        /**
         * Write generated file to filesystem. CSourceCodeWriter.writeFile will
         * correctly resolve the path to edlFileName and write the corresponding file:
         * i.e /this.tmpDir/graalsgx_ecalls_proxy.hpp
         */
        writer.writeFile(proxyFileName);
    }

    /**
     * Writes the hpp file which contains ocall definitions. These definitions are
     * the real routines which run in the enclave and call the corresponding
     * entrypoint method. Then generated file: graalsgx_out.hpp will be included in
     * App.cpp in the sgx module.
     */
    public void writeOcallDefs(List<HostedMethod> methods) {
        SGXProxyWriter writer = new SGXProxyWriter(this.tmpDir);
        assert writer != null : "SGXProxyGenerator code writer null";

        writer.appendln(headerComment);
        writer.appendln();
        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("extern \"C\" {");
        writer.appendln("#endif");
        writer.appendln();
        methods.forEach(m -> writeCMethodBody(m, writer, SGXHeader.OCALL));

        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("}");
        writer.appendln("#endif");

        /**
         * Write generated file to filesystem. CSourceCodeWriter.writeFile will
         * correctly resolve the path to edlFileName and write the corresponding file:
         * i.e /this.tmpDir/graalsgx_ocalls.hpp
         */
        writer.writeFile(sourceFileName);

    }

    /**
     * Writes the hpp file which contains the proxy methods which will call the
     * appropriate ocall routines. The generated file: ocall_proxy.hpp will be
     * included in Enclave.cpp in the sgx module.
     */
    public void writeOcallProxies(List<HostedMethod> methods) {
        SGXProxyWriter writer = new SGXProxyWriter(this.tmpDir);
        assert writer != null : "SGXProxyGenerator code writer null";

        writer.appendln(headerComment);
        writer.appendln();

        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("extern \"C\" {");
        writer.appendln("#endif");
        writer.appendln();
        methods.forEach(m -> writeCMethodBody(m, writer, SGXHeader.PROXY));

        writer.appendln("#if defined(__cplusplus)");
        writer.appendln("}");
        writer.appendln("#endif");

        /**
         * Write generated file to filesystem. CSourceCodeWriter.writeFile will
         * correctly resolve the path to edlFileName and write the corresponding file:
         * i.e /this.tmpDir/graalsgx_ocalls_proxy.hpp
         */
        writer.writeFile(proxyFileName);

    }

    /** Copy generated files and delete temporary directory */
    public void copyGenFiles() {

    }

    /**
     * Write EDL method headers. These are slightly different from C headers but
     * worth a different method on its own because of the different direction
     * attributes for specific cases.
     */
    public void writeEdlMethodHeader(HostedMethod m, CSourceCodeWriter writer) {
        assert Modifier.isStatic(m.getModifiers()) : "SGX transition function must be static.";
        String namePrefix = this.isSecure ? "graalsgx_ecall_" : "graalsgx_ocall_";

        // ecalls should be decorated as public in EDL files
        String accessModifier = this.isSecure ? "public " : "";

        writer.indents().append(accessModifier);
        // AnnotatedType annotatedReturnType = getAnnotatedReturnType(m);
        String returnType = SGXProxyWriter.toCTypeName(m,
                (ResolvedJavaType) m.getSignature().getReturnType(m.getDeclaringClass()), null, false, false,
                hMetaAccess, nativeLibs);
        writer.append(returnType);
        writer.append(space);
        writer.append(namePrefix + m.getName());
        writer.append("(");

        String sep = ", ";
        // AnnotatedType[] annotatedParameterTypes = getAnnotatedParameterTypes(m);
        Parameter[] parameters = m.getParameters();
        assert parameters != null;

        /**
         * First parameter is isolate pointer and second parameter is proxy object hash.
         * Make isolate ptr a void pointer with [user_check] sgx direction attribute.
         * After a few changes, this parameter may not be needed because the
         * corresponding isolate thread will be generated in many of the cases. And for
         * ocalls, an ecall isolate cannot be used. Nonetheless, lets keep this "dummy"
         * isolate parameter for now. It may be useful in the future.
         */

        int paramCount = m.getSignature().getParameterCount(false);
        String param0 = paramCount < 2 ? "[user_check]void *iso_thread" : "[user_check]void *iso_thread";
        writer.append(param0);
        String param = "param_";
        String cTypeName = "";

        // write remaining parameter names i.e 1 to n-1
        for (int i = 1; i < paramCount; i++) {
            writer.append(sep);
            // sep = ", ";
            cTypeName = SGXProxyWriter.toCTypeName(m,
                    (ResolvedJavaType) m.getSignature().getParameterType(i, m.getDeclaringClass()), null, false, false,
                    hMetaAccess, nativeLibs);

            /**
             * All ccharpointer params added by the bytecode instrumenter are followed by
             * the array size
             */
            if (isCCharPtr(cTypeName)) {
                String prefix = "[in, count=" + param + (i + 1) + "]";
                /**
                 * The third param of all relay methods is the return buffer pointer. This is
                 * used only by methods with object return types, but it is added nevertheless
                 * to all relay methods for now. Will optimize in a later version.
                 */
                if (!isRelayConstr(m) && i == 2) {
                    prefix = "[out, count=" + param + (i + 1) + "]";
                    //prefix = "[user_check]";
                }

                // String prefix = "[in, size=3]"; //test
                writer.append(prefix + cTypeName);

            } else {

                writer.append(cTypeName);

            }
            writer.append(space);
            writer.append(param + i);

        }
        writer.appendln(");");
        writer.appendln();

    }

    /** Write C method header: ret name (params...) */
    public void writeCMethodHeader(HostedMethod m, CSourceCodeWriter writer, SGXHeader type) {
        assert Modifier.isStatic(m.getModifiers()) : "SGX transition function must be static.";
        String namePrefix = "";
        int paramCount = m.getSignature().getParameterCount(false);
        // String sep = paramCount < 2 ? "" : ", ";
        String sep = ", ";
        boolean skipParam0 = false;

        String param0 = "";
        switch (type) {
        case OCALL:
            namePrefix = "graalsgx_ocall_";
            param0 = "void *param_0";
            skipParam0 = true;
            break;

        case ECALL:
            namePrefix = "graalsgx_ecall_";
            param0 = "void *param_0";
            skipParam0 = true;
            break;
        case PROXY:
            if (isEmptyMethod(m)) {
                namePrefix = this.isSecure ? "ocall_" : "ecall_";
            } else {
                namePrefix = this.isSecure ? "ecall_" : "ocall_";
            }

            break;

        default:
            break;
        }

        String returnType = SGXProxyWriter.toCTypeName(m,
                (ResolvedJavaType) m.getSignature().getReturnType(m.getDeclaringClass()), null, false, false,
                hMetaAccess, nativeLibs);

        // append return type
        writer.indents().append(returnType);
        writer.append(" ");
        writer.append(namePrefix + m.getName());
        // writer.append(" ");
        writer.append("(");

        // sep = ", ";
        // AnnotatedType[] annotatedParameterTypes = getAnnotatedParameterTypes(m);
        Parameter[] parameters = m.getParameters();
        assert parameters != null;

        writer.append(param0);
        sep = skipParam0 ? ", " : "";
        int start = skipParam0 ? 1 : 0;
        for (int i = start; i < paramCount; i++) {
            writer.append(sep);
            sep = ", ";
            writer.append(SGXProxyWriter.toCTypeName(m,
                    (ResolvedJavaType) m.getSignature().getParameterType(i, m.getDeclaringClass()), null, false, false,
                    hMetaAccess, nativeLibs));

            writer.append(space);
            writer.append("param_" + i);

        }
        writer.appendln(")");
        // writer.appendln();

    }

    /** Write C method body */
    public void writeCMethodBody(HostedMethod m, CSourceCodeWriter writer, SGXHeader type) {
        String returnType = SGXProxyWriter.toCTypeName(m,
                (ResolvedJavaType) m.getSignature().getReturnType(m.getDeclaringClass()), null, false, false,
                hMetaAccess, nativeLibs);
        boolean voidReturn = returnType.equals("void");
        String retLine = voidReturn ? "" : returnType + " ret = ";

        /** Number of parameters in the function */
        int paramCount = m.getSignature().getParameterCount(false);
        String sep = ", ";

        /**
         * First parameter: this varies for ecalls, ocalls, and functions with return
         * types.
         */
        String param0 = "";
        boolean skipParam0 = false;

        writeCMethodHeader(m, writer, type);
        if (isEmptyMethod(m)) {
            writer.indents().appendln("{/* Do nothing */}");
            return;
        }
        writer.indents().appendln("{");
        writer.appendln();
        writer.indents().appendln(DEBUG_INFO);

        switch (type) {
        case ECALL:
            /** Ecalls have atleast 1 param: the isolate thread */

            // writer.indents().appendln(ENC_ISO + " = " + GRAAL_ISO_TYPE_CAST +
            // "param_0;");
            if (generate_isolate(m)) {
                TEMP_ISOLATE = "graal_isolatethread_t* temp_iso = isolate_generator();";
                DESTROY_TEMP_ISOLATE = "destroy_isolate(temp_iso);";
            } else {
                TEMP_ISOLATE = "graal_isolatethread_t* temp_iso = " + ENC_ISO + ";";
                // nothing to destroy
                DESTROY_TEMP_ISOLATE = "";
            }
            writer.indents().appendln(TEMP_ISOLATE);
            param0 = paramCount < 2 ? "temp_iso" : "temp_iso";
            // skipParam0 = true;
            writer.indents().append(retLine + m.getName() + "(");
            break;

        case OCALL:
            /** Ocalls have atleast 1 param: the isolate thread */
            // writer.indents().appendln(APP_ISO + " = " + GRAAL_ISO_TYPE_CAST +
            // "param_0;");
            if (generate_isolate(m)) {
                TEMP_ISOLATE = "graal_isolatethread_t* temp_iso = isolate_generator();";
                DESTROY_TEMP_ISOLATE = "destroy_isolate(temp_iso);";
            } else {
                TEMP_ISOLATE = "graal_isolatethread_t* temp_iso = " + APP_ISO + ";";
                // nothing to destroy
                DESTROY_TEMP_ISOLATE = "";
            }
            writer.indents().appendln(TEMP_ISOLATE);
            // param0 = paramCount < 2 ? APP_ISO : APP_ISO + sep;
            param0 = "temp_iso";
            // skipParam0 = true;
            writer.indents().append(retLine + m.getName() + "(");
            break;

        case PROXY:
            if (!voidReturn) {

                writer.indents().appendln(returnType + " ret;");

            }
            if (this.isSecure) {
                /**
                 * For an ecall that returns a value, create return val, and send its address as
                 * second param. First ecall param is the global enclave id. There will always
                 * be a third parameter(isolate thread: null in this case). It is redundant as
                 * of now because an enclave isolate will be generated to serve as execution
                 * context. Nevertheless we may need this parameter in the future.
                 * 
                 */

                // param0 = voidReturn ? GLOBAL_EID + sep + "(void*)" : GLOBAL_EID + ",
                // &ret,(void*)";
                param0 = voidReturn ? GLOBAL_EID + sep + C_NULL : GLOBAL_EID + ", &ret," + C_NULL;
                writer.indents().append("graalsgx_ecall_" + m.getName() + "(");
                // skipParam0 = true;

            } else {
                /**
                 * For an ocall that returns a value, create return val, and send its address as
                 * first param. We send null pointer for isolate: we cannot attach untrusted
                 * thread to enclave isolate. Thats my reasoning:pyuhala
                 */
                param0 = voidReturn ? "NULL" : "&ret," + "NULL";
                // param0 = paramCount < 2 ? param0 : param0;
                /**
                 * Skip param zero because the above will be appended as param0 before the for
                 * loop below
                 */

                // skipParam0 = voidReturn ? true : false;

                writer.indents().append("graalsgx_ocall_" + m.getName() + "(");

            }
            break;
        default:
            break;
        }

        sep = skipParam0 ? "" : ", ";

        writer.append(param0);
        String param = "param_";
        // int start = skipParam0 ? 1 : 0;

        for (int i = 1; i < paramCount; i++) {
            writer.append(sep);
            sep = ", ";
            writer.append("param_" + i);

        }
        writer.appendln(");");
        writer.appendln();
        if (type == SGXHeader.OCALL || type == SGXHeader.ECALL) {
            writer.indents().appendln(DESTROY_TEMP_ISOLATE);
        }

        if (!voidReturn) {

            writer.indents().appendln("return ret;");

        }
        writer.outdent();
        writer.indents().appendln("}");
        writer.appendln();

    }

    /**
     * Tests if the given type corresponds to CCharPointer type.
     * 
     * @param type
     * @return
     */
    public static boolean isCCharPtr(String type) {
        // TODO: can we test differently ? pyuhala
        if (type.contains("char") && type.contains("*")) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * creates temporary directory to store generated files.
     * 
     * @return
     */
    public synchronized Path tempDirectory() {
        /**
         * PYuhala: Useful function but we do not use it here for now. All generated
         * files are sent to the system tmp folder. That way appropriate scripts can
         * transfer the files to the sgx module easily
         */
        Path dir;
        try {
            dir = Files.createTempDirectory("sgx-proxies-");
        } catch (IOException ex) {
            throw UserError.abort("Cannot create temp directory");
        }

        return dir.toAbsolutePath();
    }

    /**
     * Determines if an isolate and isolate thread will be generated to serve as
     * execution context or not.
     * 
     * @param m Transition routine
     * @return
     */
    public boolean generate_isolate(HostedMethod m) {
        SecurityInfo sec_info = m.getAnnotation(SecurityInfo.class);
        return sec_info.gen_iso();

    }

    /**
     * Tests if the input method is a relay constructor. The latter are added by the
     * javassist bytecode instrumenter.
     * 
     * @param m
     * @return
     */
    public boolean isRelayConstr(HostedMethod m) {
        SecurityInfo sec_info = m.getAnnotation(SecurityInfo.class);
        return (sec_info.type() == "relay_constr");

    }

    /**
     * This tests for some special methods (proxy cleaners which are in both
     * runtimes) which should be empty because they will never be called all things
     * being equal. However we need their definitions to avoid linkage errors. We
     * could find a better way(e.g bytecode modifs) in the future.
     */
    public boolean isEmptyMethod(HostedMethod m) {
        // boolean isCleaner = m.getName().equals("proxyCleanupOut") ||
        // m.getName().equals("proxyCleanupIn");
        boolean extraProxyCleaner = (isSecure && m.getName().equals("mirrorCleanupOut"))
                || (!isSecure && m.getName().equals("mirrorCleanupIn"))
                || (!isSecure && m.getName().equals("doProxyCleanupIn"));

        return extraProxyCleaner;
    }

}
