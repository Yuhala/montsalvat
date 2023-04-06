/*
 * Created on Wed Jan 06 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

package jtrans;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.AnnotatedArrayType;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Collections;

import javax.script.Invocable;

import java.util.Arrays;
import jtrans.ClassFinder;

import org.graalvm.nativeimage.SGXSerializer;

//import org.apache.log4j.Logger;

import org.graalvm.nativeimage.SecurityInfo;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.function.CFunction;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtField;
import javassist.CtField.Initializer;
import javassist.CtConstructor;
import javassist.LoaderClassPath;
import javassist.Modifier;

import javassist.CtNewMethod;
import javassist.CtNewConstructor;
import javassist.bytecode.AnnotationsAttribute;
import javassist.bytecode.AccessFlag;
import javassist.bytecode.ClassFile;
import javassist.bytecode.ConstPool;
import javassist.bytecode.annotation.Annotation;
import javassist.bytecode.annotation.StringMemberValue;
import javassist.bytecode.annotation.ClassMemberValue;
import javassist.bytecode.annotation.MemberValue;
import javassist.bytecode.MethodInfo;

/** Used to specify the class/object type of an object parameter */
enum OBJTYPE {
    /** The object is an instance of a proxy/stripped class */
    PROXY,
    /**
     * This object is an instance of a concrete (not proxy) annotated class (but not
     * a mirror object) or is a mirror object. Concrete objects which are not yet
     * mirror objects will be made mirror objects after a corresponding proxy is
     * created at the other end.
     */
    MIRROR,

    /**
     * Object belongs to a don't care class: ie concrete unannotated class. These
     * object parameters will be serialized
     */
    DONTCARE
}

public class JAssistClassTransformer {

    private ClassPool cpool;
    private static String trustedDir;
    private static String untrustedDir;
    private static String parent;
    private static String pkgName;
    private static List<String> classNames;
    private static List<String> trustedClasses = new ArrayList<>();
    private static List<String> untrustedClasses = new ArrayList<>();
    private static List<String> serializedClasses = new ArrayList<>();
    private boolean isTrusted;
    /**
     * The following strings represent fully-qualified names of some classes used by
     * the transformer when instrumenting classes
     */
    public static final String graalEntryPoint = "org.graalvm.nativeimage.c.function.CEntryPoint";
    public static final String sgxSecurityInfo = "org.graalvm.nativeimage.SecurityInfo";
    public static final String pointer = "org.graalvm.word.Pointer";
    public static final String ccharpointer = "org.graalvm.nativeimage.c.type.CCharPointer";
    public static final String nullPointer = "org.graalvm.word.WordFactory.nullPointer();";
    public static final String isoThread = "org.graalvm.nativeimage.IsolateThread";
    public static final String currentIso = "org.graalvm.nativeimage.CurrentIsolate";
    public static final String cFunction = "org.graalvm.nativeimage.c.function.CFunction";
    public static final String sgxObjTrans = "org.graalvm.nativeimage.SGXObjectTranslator";
    public static final String proxyCleaner = "  org.graalvm.nativeimage.ProxyCleaner";
    public static final String getProxy = proxyCleaner + ".getProxy";
    public static final String setSecurity = sgxObjTrans + ".setSecurity";
    public static final String serializer = "org.graalvm.nativeimage.SGXSerializer";
    public static final String sgxSerialize = serializer + ".serialize";
    public static final String sgxDeserialize = serializer + ".deserialize";
    public static final String getCharPointer = serializer + ".getCharPointer";
    public static final String getByteBuffer = serializer + ".getByteBuffer";
    public static final String arrayCopy = serializer + ".arrayCopy";
    public static final String zeroFill = serializer + ".zeroFill";
    public static final String isMirrorObj = sgxObjTrans + ".isMirrorObject";
    public static final String getProxyHash = sgxObjTrans + ".getProxyHash";
    public static final String putReturnVal = sgxObjTrans + ".putReturnVal";
    public static final String getReturnVal = sgxObjTrans + ".getReturnVal";
    public static final String removeReturnVal = sgxObjTrans + ".removeReturnVal";

    public static final String throwException = "throws Exception";

    /** CEntryPoint options */
    public static final String cEntryPointOptions = "com.oracle.svm.core.c.function.CEntryPointOptions";
    public static final String doNotInclude = "com.oracle.svm.core.c.function.CEntryPointOptions.NotIncludedAutomatically";

    /** Separators */
    public static final String space = " ";
    public static final String comma = ",";
    public static final String semiColon = ";";

    /** Other useful string commands used during instrumentations */
    public static final String setProxyHash = "$0.proxyHash = " + sgxObjTrans + ".hash($0);";
    public static final String hashObject = sgxObjTrans + ".hash";
    // public static final String initRetMap = "returnObjects = new HashMap();";
    public static final String putProxyObject = proxyCleaner + ".add($0,$0.proxyHash);";
    public static final String incProxyObjects = sgxObjTrans + ".incNumProxies();";
    public static final String getCurIso = isoThread + space + "iso" + space + "=" + space + currentIso
            + ".getCurrentThread();";

    // size of return buffers
    public static final int BUFSIZ = 128;

    /**
     * @param security represents the native image security family this transformer
     *                 is instrumenting classes for. The class search path will be
     *                 changed accordingly. Java assist modifies the class files
     *                 differently for each security family so its important to have
     *                 copies of the classes on different class paths which will be
     *                 used by the transformer accordingly.
     */
    public JAssistClassTransformer(String parentDir, String pkg, boolean security) {

        this.isTrusted = security;
        this.cpool = ClassPool.getDefault();
        trustedDir = parentDir + "/trusted";
        untrustedDir = parentDir + "/untrusted";
        parent = parentDir;
        pkgName = pkg;

    }

    /** Transform class bytecodes accordingly */
    public void transformClasses() throws Exception {

        if (trustedClasses.isEmpty() && untrustedClasses.isEmpty()) {
            ClassFinder finder = new ClassFinder(parent, pkgName, getCLoader(this.isTrusted, parent));
            trustedClasses = finder.getTrustedClasses();
            untrustedClasses = finder.getUntrustedClasses();
            printAnnotatedClass();
        }

        /**
         * Append trusted dir to head of search path for trusted image gen and untrusted
         * dir for untrusted image gen.
         */
        // System.out.println("Class search path is: " + this.cpool.toString());
        if (this.isTrusted) {
            try {
                this.cpool.insertClassPath(trustedDir);

            } catch (Exception e) {
                System.out.println("Could not insert trusted path to cp");
                e.getStackTrace();
            }
            this.transformTrusted();
        } else {
            try {
                this.cpool.insertClassPath(untrustedDir);
            } catch (Exception e) {
                System.out.println("Could not insert untrusted path to cp");
                e.getStackTrace();
            }
            this.transformUntrusted();
        }

        String type = this.isTrusted ? "Trusted image" : "Untrusted image";
        System.out.println("############## " + type + " instrumentation complete ###############: ");

    }

    /**
     * Transform classes for trusted image generation. Modified class files are
     * found in the trusted subdirectory. For trusted classes, static (graal
     * CEntryPoints) relay methods are added for each class method, which perform
     * "object translation" with the help of the SGXObjectTranslator. The
     * corresponding instance method is then called for the object. For static class
     * methods, the method is simply called without any object translation. For
     * untrusted classes, all their methods are stripped and replaced with code
     * which will perform an ocall transition to the appropriate relay function in
     * the untrusted runtime. The hashcode of the calling object is sent if it is
     * non static as well as the passed parameters. Object parameters are serialized
     * into a byte array/ccharpointer. The size of this array will be the next
     * parameter. It will be passed via an ocall using the "in" keyword from the
     * Intel SGX SDK to the untrusted runtime.
     */
    public synchronized void transformTrusted() throws Exception {

        CtMethod[] classMethods = null;
        CtConstructor[] classConstructors = null;

        CtClass secClass = null;
        CtClass unsecClass = null;
        /**
         * For trusted classes, add corresponding relay methods for constructors and
         * class methods.
         */
        for (String cname : this.trustedClasses) {
            // System.out.println("this trusted class name: "+cname);

            secClass = cpool.get(cname);
            // System.out.println("WriteDir test: " + writeDir);

            /*
             * if (secClass.isFrozen()) { secClass.defrost(); }
             */
            String simple = secClass.getSimpleName();
            classMethods = secClass.getDeclaredMethods();
            classConstructors = secClass.getDeclaredConstructors();

            // System.out.println("Class name: " + simple);

            for (int i = 0; i < classConstructors.length; i++) {
                CtConstructor ctor = classConstructors[i];
                this.addRelayConstructor(secClass, ctor);
            }
            /** this method is used in the relay methods and should be added b4 */
            // this.addNativeRetCopy(secClass);

            for (int i = 0; i < classMethods.length; i++) {
                CtMethod m = classMethods[i];
                this.addRelayMethod(secClass, m);

            }

            /** Save changes in new class file in trusted folder */
            String writeDir = "";// getParentDir(cname.replace('.', '/'));
            secClass.writeFile(trustedDir);
            // System.out.println("Full writefile path: " + trustedDir + writeDir);
            /**
             * Hack to avoid frozen class issues. If it persists try using child classpools
             * and childFirstLookup = true. Ref:
             * https://www.javassist.org/tutorial/tutorial.html
             */
            secClass.detach();

        }
        /**
         * For untrusted classes, strip all the methods and replace with ocalls: we are
         * creating classes for the trusted image build so enclave transitions are
         * ocalls.
         */
        for (String cname : this.untrustedClasses) {

            // String writeDir = getParentDir(cname.replace('.', '/'));
            unsecClass = cpool.get(cname);
            /*
             * if (unsecClass.isFrozen()) { unsecClass.defrost(); }
             */
            String simple = unsecClass.getSimpleName();
            classMethods = unsecClass.getDeclaredMethods();
            classConstructors = unsecClass.getDeclaredConstructors();

            // System.out.println("Class name: " + simple);

            /**
             * Add field for proxy object hash value. This way we don't need to recalculate
             * it for every proxy method invocation.
             */
            this.addProxyFields(unsecClass);
            for (int i = 0; i < classConstructors.length; i++) {
                CtConstructor ctor = classConstructors[i];
                this.addNativeMethod(unsecClass, ctor, true);
                this.addProxyConstructor(ctor);

            }
            // this.overloadProxyConstructor(unsecClass);
            // this.addRetCopy(unsecClass);

            for (int i = 0; i < classMethods.length; i++) {
                CtMethod m = classMethods[i];
                this.addNativeMethod(unsecClass, m, false);
                this.addProxyMethod(m);

            }

            /** Save changes in new class file in trusted folder */
            unsecClass.writeFile(trustedDir);
            unsecClass.detach();
        }

    }

    /**
     * Transform classes for untrusted image generation. Modified class files are
     * found in the untrusted subdirectory. For untrusted classes, static (graal
     * CEntryPoints) relay methods are added for each class method, which perform
     * "object translation" with the help of the SGXObjectTranslator. The
     * corresponding instance method is then called for the object. For static class
     * methods, the method is simply called without any object translation. For
     * trusted classes, all their methods are stripped and replaced with code which
     * will perform an ecall transition to the appropriate relay function in the
     * trusted runtime. The hashcode of the calling object is sent if it is non
     * static as well as the passed parameters. Object parameters are serialized
     * into a byte array/ccharpointer. The size of this array will be the next
     * parameter. It will be passed across the enclave transition boundary using the
     * "in" keyword from the Intel SGX SDK to the trusted runtime.
     * 
     */
    public synchronized void transformUntrusted() throws Exception {
        CtMethod[] classMethods = null;
        CtConstructor[] classConstructors = null;

        CtClass secClass = null;
        CtClass unsecClass = null;
        /**
         * For untrusted classes, add corresponding relay methods for constructors and
         * class methods.
         */
        for (String cname : this.untrustedClasses) {

            // String writeDir = getParentDir(cname.replace('.', '/'));
            unsecClass = cpool.get(cname);
            /*
             * if (unsecClass.isFrozen()) { unsecClass.defrost(); }
             */
            String simple = unsecClass.getSimpleName();
            classMethods = unsecClass.getDeclaredMethods();
            classConstructors = unsecClass.getDeclaredConstructors();

            // System.out.println("Class name: " + simple);
            // this.addNativeRetCopy(unsecClass);

            for (int i = 0; i < classConstructors.length; i++) {
                CtConstructor ctor = classConstructors[i];
                this.addRelayConstructor(unsecClass, ctor);
            }

            for (int i = 0; i < classMethods.length; i++) {
                CtMethod m = classMethods[i];
                this.addRelayMethod(unsecClass, m);

            }

            /** Save changes in new class file in trusted folder */
            unsecClass.writeFile(untrustedDir);
            unsecClass.detach();

        }
        /**
         * For trusted classes, strip all the methods and replace with ecalls: we are
         * creating classes for the untrusted image build so enclave transitions are
         * ecalls.
         */
        for (String cname : this.trustedClasses) {

            // String writeDir = getParentDir(cname.replace('.', '/'));
            secClass = cpool.get(cname);
            /*
             * if (secClass.isFrozen()) { secClass.defrost(); }
             */
            String simple = secClass.getSimpleName();
            classMethods = secClass.getDeclaredMethods();
            classConstructors = secClass.getDeclaredConstructors();

            // System.out.println("Class name: " + simple);

            /**
             * Add field for proxy object hash value. This way we don't need to recalculate
             * it for every proxy method invocation.
             */
            this.addProxyFields(secClass);
            for (int i = 0; i < classConstructors.length; i++) {
                CtConstructor ctor = classConstructors[i];
                this.addNativeMethod(secClass, ctor, true);
                this.addProxyConstructor(ctor);

            }
            // this.overloadProxyConstructor(secClass);
            // this.addRetCopy(secClass);

            for (int i = 0; i < classMethods.length; i++) {
                CtMethod m = classMethods[i];
                this.addNativeMethod(secClass, m, false);
                this.addProxyMethod(m);

            }

            /** Save changes in new class file in trusted folder */
            secClass.writeFile(untrustedDir);
            secClass.detach();
        }
    }

    /**
     * This method creates a corresponding relay constructor for the given class
     * constructor. The relay constructor is a graal entrypoint method which
     * instantiates a mirror object for the given proxy object. The hashcode of the
     * proxy object and the new mirror object are added to the SGX translator
     * registry upon successful creation.
     */

    public void addRelayConstructor(CtClass cls, CtConstructor ctor) throws Exception {
        CtClass[] cParams = ctor.getParameterTypes();
        String relayParams = getRelayParams(cParams, cls, true);
        String relayHeader = "static void relay_" + ctor.getName() + relayParams;
        String relayBody = this.getConstRelayBody(cls, ctor);

        // System.out.println("Constructor name: " + ctor.getName());
        // System.out.println("Relay constructor header: " + relayHeader);
        // System.out.println("Relay constructor body: " + relayBody);

        String source = relayHeader + relayBody;
        /** Build new method with factory method */
        try {
            // NB: the relay constructor is also a CtMethod
            CtMethod relayCtor = CtNewMethod.make(source, cls);

            this.addSgxAnnotation(cls, relayCtor, true);
            this.addGraalAnnotation(cls, relayCtor);
            cls.addMethod(relayCtor);

        } catch (Exception e) {
            e.printStackTrace();
        }
        // cls.addMethod(relayMethod);

    }

    /**
     * Each proxy class needs this method to handle serialized return types: not
     * used anymore
     */
    public void addRetCopy(CtClass cls) throws Exception {

        String methodName = "retCopy_" + getSimpleName(cls.getName());
        String params = "(" + isoThread + space + "iso";
        params += comma + ccharpointer + space + "ptr, int len, int hash)";

        String methodHeader = "static void " + methodName + params;

        // Deserialize the returned buffer to generic object
        String code = "byte[] retBytes" + space + "=" + space + getByteBuffer + "(ptr,len);";
        code += "Object retObj" + space + "=" + space + sgxDeserialize + "(retBytes);";
        // code += "returnObjects.put(Integer.valueOf(hash),retObj);";
        code += putReturnVal + "(hash,retObj);";
        // code += "System.out.println(\"Adding return obj for proxy: \"+hash);";
        // code += "java.lang.Thread.sleep(2000);";
        code += "if(retObj == null){System.out.println(\"Return object is null: method-retCopy\");}";

        // code += "String obj = (String)returnObjects.get(Integer.valueOf(hash));"; //
        // generic return object
        code += "String obj = (String)" + getReturnVal + "(hash);";
        code += "System.out.println(\"Added return object to map: \"+obj);";
        String methodBody = "{" + code + "}";

        // returnObjects.put(hash,ptr);
        String src = methodHeader + methodBody;

        /** Build method with jassist factory method */
        try {

            CtMethod newMethod = CtNewMethod.make(src, cls);

            this.addSgxAnnotation(cls, newMethod, false);
            this.addGraalAnnotation(cls, newMethod);
            cls.addMethod(newMethod);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Adds a native method prototype for the corresponding object marshalling
     * method: not used anymore
     * 
     * @param cls
     * @throws Exception
     */
    public void addNativeRetCopy(CtClass cls) throws Exception {

        String transitionType = this.isTrusted ? "ocall" : "ecall";
        String methodName = transitionType + "_retCopy_" + getSimpleName(cls.getName());
        String params = "(" + isoThread + space + "iso";
        params += comma + ccharpointer + space + "ptr, int len, int hash);";

        String nativeHeader = "void" + space + methodName + params;

        /** Build native method with factory method */
        try {
            CtMethod nativeMethod = CtNewMethod.make(nativeHeader, cls);
            nativeMethod.setModifiers(Modifier.PUBLIC | Modifier.STATIC | Modifier.NATIVE);
            addCFuncAnnotation(nativeMethod);
            cls.addMethod(nativeMethod);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Overload proxy class constructor. This is a special constructor to create
     * proxy objects for mirror objects that already exist. These proxy constructors
     * are useful when mirror objects are method parameters which have to be
     * "passed" across the enclave boundary.
     * 
     * @param cls
     * @throws Exception
     */
    public void overloadProxyConstructor(CtClass cls) throws Exception {
        // 1. Add overloaded constructor
        // contains the different param counts of the class's constructors
        ArrayList<Integer> list = new ArrayList<Integer>();
        CtConstructor[] ctors = cls.getDeclaredConstructors();
        String cname = ctors[0].getName();
        String callingParams = "";

        for (int i = 0; i < ctors.length; i++) {
            CtConstructor ctor = ctors[i];
            CtClass[] cParams = ctor.getParameterTypes();
            list.add(cParams.length);
        }
        int paramNum = getOverloadParamNum(list);
        String params = "";
        String sep;
        if (paramNum == 0) {
            params = "()";
            callingParams = "()";
        } else {
            for (int i = 0; i < paramNum; i++) {
                sep = (i == 0) ? "(" : ",";
                params += sep + " int param" + i;
                callingParams += sep + "0";
            }
            params += ")";
            callingParams += ")";
        }
        String ctorHeader = "public" + space + cname + params;
        String ctorSource = ctorHeader + "{" + setProxyHash + putProxyObject
                + "System.out.println(\"Dynamic proxy created\");}";

        /** Build new constructor with factory method */
        try {

            CtConstructor proxyOverload = CtNewConstructor.make(ctorSource, cls);
            cls.addConstructor(proxyOverload);

        } catch (Exception e) {
            e.printStackTrace();
        }

        // 2. Add entrypoint to constructor
        String entryName = "overload_" + cname;
        String entryHeader = "static int " + entryName + "(" + isoThread + space + "iso)";
        String entryBody = "{" + cls.getName() + space + "proxy = new " + cls.getName() + callingParams + semiColon;
        entryBody += "return proxy.proxyHash;}";
        String entrySource = entryHeader + entryBody;

        // System.out.println("Entry source: " + entrySource);
        /** Build entrypoint method with factory method */
        try {
            CtMethod entryOverload = CtNewMethod.make(entrySource, cls);

            this.addSgxAnnotation(cls, entryOverload, true);
            this.addGraalAnnotation(cls, entryOverload);
            cls.addMethod(entryOverload);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Since all overloaded constructors must have different signatures, we need to
     * find a way to get a different signature for our overloaded proxy constructor.
     * The parameters of this constructor are not useful to us. We just need a
     * different signature from all the other constructors. We do it by using an
     * "all int parameter" constructor. The number of ints (n) depends on the number
     * of params in the other constructors: it is the smallest integer >=0 diff from
     * all the constructor param counts. We will call this constructor with n 0s.
     * NB: this is more of a "hack" and can probably be done another way.
     * 
     * @param list
     * @return
     */
    public int getOverloadParamNum(ArrayList<Integer> list) {
        int max = Collections.max(list);
        int ret = max + 1;
        for (int i = 0; i <= (max + 1); i++) {
            if (!list.contains(i)) {
                ret = i;
                break;
            }
        }
        return ret;
    }

    /**
     * Adds a transition function for overloaded proxy constructor.
     * 
     * @param cls
     * @param paramType
     */
    static void addNativeOverload(CtClass cls, String paramType, String transitionType) throws Exception {
        // String transitionType = this.isTrusted ? "ocall" : "ecall";
        // name of transition routine e.g ecall_overload_Type
        String cname = transitionType + "_overload_" + getSimpleName(paramType);
        String params = "(" + isoThread + space + "iso)";
        // method will return created proxy hash

        String nativeHeader = "int" + space + cname + params + semiColon;

        // System.out.println("Native overload header: " + nativeHeader);

        /** Build native method with factory method */
        try {
            CtMethod nativeMethod = CtNewMethod.make(nativeHeader, cls);
            nativeMethod.setModifiers(Modifier.PUBLIC | Modifier.STATIC | Modifier.NATIVE);
            addCFuncAnnotation(nativeMethod);
            cls.addMethod(nativeMethod);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method creates a corresponding relay method for a given class method.
     * The relay method is a graal entrypoint method (static + CEntryPoint
     * annotation). It constructs a giant string which represents the whole method.
     * This string will then be sent to a java assist factory method to construct
     * the final CtMethod which will be added to the class.
     */
    public void addRelayMethod(CtClass cls, CtMethod m) throws Exception {
        /** Make no relay method for main */
        if (m.getName().equals("main")) {
            System.out.println("--------------- Skipping relay method for main method ----------------");
            return;
        } else if (m.getName().contains("$")) {
            System.out.println("--------------- Method name contains illegal xter: skipping relay ----------------");
            return;
        }
        System.out.println("Adding relay method: " + m.getName());
        // System.identityHashCode(obj);
        CtClass[] mParams = m.getParameterTypes();
        String retType = m.getReturnType().getName();
        String relayParams = getRelayParams(mParams, cls, false);

        String typeTest = getRelayType(retType);
        if (typeTest.equals(ccharpointer)) {
            /**
             * Methods with object return types will return ints = proxy hash or length of
             * serialized object
             */
            retType = "int";
        }

        // check for $ in method name and replace
        String mName = m.getName();

        String relayHeader = "static" + space + retType + space + "relay_" + mName + relayParams;

        String relayBody = this.getMethodRelayBody(cls, m);

        // System.out.println("Method name: " + m.getName());
        // System.out.println("Relay method header: " + relayHeader);
        // System.out.println("Relay body: " + relayBody);

        String source = relayHeader + relayBody;
        /** Build new method with factory method */
        try {
            CtMethod relayMethod = CtNewMethod.make(source, cls);

            this.addSgxAnnotation(cls, relayMethod, false);
            this.addGraalAnnotation(cls, relayMethod);
            cls.addMethod(relayMethod);

        } catch (Exception e) {
            e.printStackTrace();
        }
        // cls.addMethod(relayMethod);

    }

    /**
     * This method strips class constructors and replaces their bodies with
     * transitions (ocall or ecall) to the corresponding relay constructor in the
     * opposite runtime. The associated proxy object is added first A corresponding
     * native interface corresponding to the ocall/ecall is added. The latter will
     * be generated by the sgx proxy generator.
     */
    public void addProxyConstructor(CtConstructor ctor) throws Exception {

        try {
            String source = this.getProxyCtorBody(ctor);
            ctor.setBody(source);
        } catch (Exception e) {
            e.getStackTrace();
        }

    }

    /**
     * This method strips class methods and replaces their bodies with transitions
     * (ocall or ecall) to the corresponding relay methods in the opposite runtime.
     * A corresponding native interface corresponding to the ocall/ecall is added.
     * The latter will be generated by the sgx proxy generator.
     */
    public void addProxyMethod(CtMethod m) throws Exception {
        // skip any native methods
        int mod = m.getModifiers();
        boolean isMain = isMainMethod(m) && Modifier.isPublic(mod) && Modifier.isStatic(mod);
        boolean isNative = Modifier.isNative(mod);
        String mbody = "";

        if (!isNative && !isMain) {
            try {
                mbody = this.getProxyMethodBody(m);
                m.setBody(mbody);
            } catch (Exception e) {
                e.getStackTrace();
            }
        }

    }

    /**
     * Adds a native method to a class. These native methods are responsible for
     * performing the enclave transitions.
     */
    public void addNativeMethod(CtClass cls, Object obj, boolean isConstructor) throws Exception {

        CtClass[] mParams = null;
        String retType = null;
        String name = null;
        String relayParams = null;
        String nativeHeader = null;

        /**
         * Native methods are added only to the proxy classes. So for trusted image
         * generation (this.isTrusted = true) they will be ocalls and for untrusted
         * image generation (this.isTrusted = false) they will be ecalls
         */
        String transitionType = this.isTrusted ? "ocall" : "ecall";

        /** Test if obj is constructor of method */
        if (isConstructor) {
            CtConstructor ctor = (CtConstructor) obj;
            mParams = ctor.getParameterTypes();
            name = ctor.getName();
            retType = "void";

        } else {
            CtMethod m = (CtMethod) obj;
            mParams = m.getParameterTypes();
            retType = m.getReturnType().getName();
            // remove $
            name = m.getName();

            if (name.contains("$")) {
                System.out
                        .println("--------------- Method name contains illegal xter: skipping native ----------------");
                return;
            }
            // skip any native methods
            int mod = m.getModifiers();
            boolean isNative = Modifier.isNative(mod);
            if (isNative || isMainMethod(m)) {
                return;
            }

        }

        String relayType = getRelayType(retType);
        if (relayType.equals(ccharpointer)) {
            /**
             * Methods with object return types return ints = proxy hash or serialized
             * object length
             */
            retType = "int";
        }

        relayParams = getRelayParams(mParams, cls, isConstructor);
        nativeHeader = retType + space + transitionType + "_relay_" + name + relayParams + semiColon;

        /** Build native method with factory method */
        try {
            CtMethod nativeMethod = CtNewMethod.make(nativeHeader, cls);
            nativeMethod.setModifiers(Modifier.PUBLIC | Modifier.STATIC | Modifier.NATIVE);
            addCFuncAnnotation(nativeMethod);
            cls.addMethod(nativeMethod);
            // cls.setModifiers(cls.getModifiers() & ~Modifier.ABSTRACT);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Create field to store proxy object hashcode and deserialized object return
     * values for proxy objects. The hash field will be assigned the object hash
     * value once in the class constructor
     */
    public void addProxyFields(CtClass cls) throws Exception {
        CtField hashField = CtField.make("public final int proxyHash;", cls);
        // CtField returnPtrs = CtField.make("HashMap<Integer," + ccharpointer + ">
        // returnObjects;", cls);

        // TODO: use generic arguments for the hashmap
        // Get handle to HashMap class.
        CtClass hashMapClass = this.cpool.getDefault().get("java.util.HashMap");
        CtField returnPtrs = new CtField(hashMapClass, "returnObjects", cls);
        returnPtrs.setModifiers(Modifier.PRIVATE | Modifier.STATIC | Modifier.FINAL);
        // new HashMap<>()

        cls.addField(hashField);
        // cls.addField(returnPtrs, CtField.Initializer.byNew(hashMapClass));
        cls.addField(returnPtrs, CtField.Initializer.byExpr("new java.util.HashMap();"));
    }

    /** Build and return stripped proxy constructor body */
    public String getProxyCtorBody(CtConstructor ctor) throws Exception {
        /** We use this flag to decide if we throw exception or not in constructor */
        boolean hasObjectParam = false;

        CtClass[] mParams = ctor.getParameterTypes();
        // String relayParams = getRelayParams(mParams);//use this to detect object
        // types

        /** Serialization code if applicable */
        String serializeCode = "";
        /** Code to handle proxy or mirror params */
        String handleProxy = "";
        String handleMirror = "";
        String relayType;
        String realType;
        CtClass ctClass = ctor.getDeclaringClass();
        String className = ctClass.getName();

        /**
         * We strip untrusted classes during trusted image gen and vice versa. So proxy
         * classes do ocalls during trusted image generation and ecalls during untrusted
         * image generation.
         */
        String transitionType = this.isTrusted ? "ocall" : "ecall";

        /**
         * Build the param list for performing the enclave transition.
         * 
         */
        String enclaveTrans = "(iso,$0.proxyHash";

        for (int i = 0; i < mParams.length; i++) {

            realType = mParams[i].getName();
            relayType = getRelayType(realType);// fully qualified name
            if (hasObject(relayType)) {
                OBJTYPE objType = getObjectType(realType, className);

                switch (objType) {
                    case PROXY:
                        handleProxy += sendProxy(i, realType);
                        enclaveTrans += comma + "proxyHash" + i;
                        break;

                    case MIRROR:
                        handleMirror += sendMirror(i, realType, ctClass, transitionType);
                        enclaveTrans += comma + "proxyHash" + i;
                        break;

                    case DONTCARE:
                        serializeCode += serializeParam(i);
                        enclaveTrans += comma + "buffer" + i + comma + "len" + i;
                        break;

                    default:
                        break;
                }

            } else {
                // NB: $0 = this
                enclaveTrans += comma + "$" + (i + 1);
            }

        }
        enclaveTrans += ");";

        enclaveTrans = transitionType + "_relay_" + ctor.getName() + enclaveTrans;

        String securitySet = this.isTrusted ? setSecurity + "(true);" : setSecurity + "(false);";
        // String ex = hasObjectParam ? throwException : "";

        // concatenation order should not be changed!
        String newBody = "{" + handleMirror + handleProxy + serializeCode + getCurIso + setProxyHash + putProxyObject
                + enclaveTrans + "}";
        // System.out.println("Stripped constructor body: " + newBody);

        return newBody;
    }

    /** Build and return stripped proxy method body */
    public String getProxyMethodBody(CtMethod m) throws Exception {

        /** We use this flag to decide if we throw exception or not in constructor */
        boolean hasObjectParam = false;

        /** Serialization code if applicable */
        String serializeCode = "";
        /** Code to handle proxy or mirror params */
        String handleProxy = "";
        String handleMirror = "";

        String relayType;
        String realType;

        CtClass ctClass = m.getDeclaringClass();
        String className = ctClass.getName();

        CtClass[] mParams = m.getParameterTypes();
        String retType = m.getReturnType().getName();
        // String relayParams = getRelayParams(mParams);//use this to detect object
        // types
        int mod = m.getModifiers();
        boolean isStatic = Modifier.isStatic(mod);
        /**
         * We strip untrusted classes during trusted image gen and vice versa. So proxy
         * classes do ocalls during trusted image generation and ecalls during untrusted
         * image generation.
         */
        String transitionType = this.isTrusted ? "ocall" : "ecall";

        /**
         * All proxy methods have a buffer input param which will contain any returned
         * byte array. Methods which return primitive types will not read this buffer.
         */
        String retBuf = "byte[] retBuf = new byte[" + BUFSIZ + "];";
        String retPtr = ccharpointer + space + "retPtr = " + getCharPointer + "(retBuf);";

        /**
         * Build the param list for performing the enclave transition. TODO: object
         * parameters will serialized here.
         */
        String enclaveTrans = "";
        if (isStatic) {
            // use hashcode of 0 for static invocations
            enclaveTrans = "(iso,0,retPtr," + BUFSIZ;
        } else {
            // use hash
            enclaveTrans = "(iso,$0.proxyHash,retPtr," + BUFSIZ;

        }

        // remove $ from method name
        String mName = m.getName();

        for (int i = 0; i < mParams.length; i++) {
            // serialize object params
            realType = mParams[i].getName();
            relayType = getRelayType(realType);
            if (hasObject(relayType)) {
                OBJTYPE objType = getObjectType(realType, className);

                switch (objType) {
                    case PROXY:
                        handleProxy += sendProxy(i, realType);
                        enclaveTrans += comma + "proxyHash" + i;
                        System.out.println("Send proxy: " + handleProxy);
                        break;

                    case MIRROR:
                        handleMirror += sendMirror(i, realType, ctClass, transitionType);
                        enclaveTrans += comma + "proxyHash" + i;
                        break;

                    case DONTCARE:
                        serializeCode += serializeParam(i);
                        enclaveTrans += comma + "buffer" + i + comma + "len" + i;
                        break;

                    default:
                        break;
                }

            } else {
                // NB: $0 = this
                enclaveTrans += comma + "$" + (i + 1);
            }

        }
        enclaveTrans += ");";

        enclaveTrans = transitionType + "_relay_" + mName + enclaveTrans;

        if (!retType.equals("void")) {

            enclaveTrans = resolveProxyReturn(retType, className, enclaveTrans, isStatic);

        }

        // String ex = hasObjectParam ? throwException : "";
        // NB: do not change the order of these concatenations.
        String proxyBody = "{" + getCurIso + handleMirror + handleProxy + serializeCode + retBuf + retPtr + enclaveTrans
                + "}";
        return proxyBody;

    }

    /** Builds the body of a relay constructor */
    public String getConstRelayBody(CtClass cls, CtConstructor ctor) throws Exception {
        /**
         * The first two parameters in relay method are isolate thread and proxy object
         * hashcode respectively. We call the corresponding class method with params 3++
         */
        // System.out.println("getConstRelayBody: " + cls.getName());
        int i = 3;
        CtClass[] cParams = ctor.getParameterTypes();
        String className = cls.getName();
        String callingParams = "";
        String deserializeCode = "";
        String handleProxy = "";
        String handleMirror = "";
        String relayType;
        String realType;
        String sep = "";

        if (cParams.length == 0) {
            /** Method has no parameters */
            callingParams = "()";
        } else {
            /**
             * Example serialization code: byte[] bytes0 = getByteBuffer(param0,param1);
             * String obj0 = (String)deserialize(bytes0);
             */

            // TODO: check if its a proxy class

            for (int j = 0; j < cParams.length; j++) {
                sep = (j == 0) ? "(" : ",";
                realType = cParams[j].getName();
                relayType = getRelayType(realType);
                if (hasObject(relayType)) {

                    OBJTYPE objType = getObjectType(realType, className);

                    switch (objType) {
                        case PROXY:
                            handleProxy += resolveProxy(i, realType);
                            callingParams += sep + "obj" + i;
                            i++;
                            break;

                        case MIRROR:
                            handleMirror += resolveMirror(i, realType);
                            callingParams += sep + "obj" + i;
                            i++;
                            break;

                        case DONTCARE:

                            deserializeCode += deserializeParam(i, realType);
                            registerSerializable(realType);
                            callingParams += sep + "obj" + i;
                            i += 2;
                            break;

                        default:
                            break;
                    }

                } else {
                    callingParams += sep + "param" + i;
                    i++;
                }

            }
            // Close the parentheses
            callingParams += ")";

        }

        /**
         * Code to instantiate mirror object: e.g Password mirrorObj = new
         * Password(params)
         */
        String createMirror = className + space + "mirrorObj" + space + "=" + space + "new" + space + className
                + callingParams + semiColon;

        /** Add mirror object to sgx translator mirror object registry */
        String registerMirror = sgxObjTrans + ".putMirrorObject(param2,mirrorObj);";

        String fullBody = "{" + handleMirror + handleProxy + deserializeCode + createMirror + registerMirror + "}";
        return fullBody;
    }

    /** Builds the body of a relay method */
    public String getMethodRelayBody(CtClass cls, CtMethod m) throws Exception {
        /**
         * The first two parameters in relay method are isolate thread and proxy object
         * hashcode respectively. We call the corresponding class method with params 3++
         */
        int i = 5;
        int mod = m.getModifiers();
        CtClass[] mParams = m.getParameterTypes();
        String retType = m.getReturnType().getName();

        String modString = Modifier.toString(mod);
        boolean isStatic = Modifier.isStatic(mod);
        String className = cls.getName();
        // remove $ from method name
        String methodName = m.getName();

        String deserializeCode = "";
        String handleProxy = "";
        String handleMirror = "";
        String relayType;
        String realType;
        String sep = "";

        /**
         * Relay methods in trusted RT do ocalls and relay methods in untrusted RT do
         * ecalls
         */
        String transPrefix = this.isTrusted ? "ocall" : "ecall";

        /** Translate and cast resulting object */
        String transCast = "((" + className + ")" + sgxObjTrans + ".getMirrorObject(param2))";
        String callingParams = "";
        String invocation = "";
        if (mParams.length == 0) {
            /** Method has no parameters */
            callingParams = "()";
        } else {
            /**
             * Example serialization code: byte[] bytes0 = getByteBuffer(param0,param1);
             * String obj0 = (String)deserialize(bytes0);
             */

            for (int j = 0; j < mParams.length; j++) {
                sep = (j == 0) ? "(" : ",";
                realType = mParams[j].getName();
                relayType = getRelayType(realType);
                if (hasObject(relayType)) {

                    OBJTYPE objType = getObjectType(realType, className);

                    switch (objType) {

                        case PROXY:
                            // System.out.println("Proxy param: " + realType);
                            handleProxy += resolveProxy(i, realType);
                            callingParams += sep + "obj" + i;
                            i++;
                            break;

                        case MIRROR:
                            handleMirror += resolveMirror(i, realType);
                            callingParams += sep + "obj" + i;
                            i++;
                            break;

                        case DONTCARE:

                            deserializeCode += deserializeParam(i, realType);
                            registerSerializable(realType);
                            callingParams += sep + "obj" + i;
                            i += 2;
                            break;

                        default:
                            break;
                    }

                } else {
                    callingParams += sep + "param" + i;
                    i++;
                }

            }
            // Close the parentheses
            callingParams += ")";
        }

        // System.out.println("Relay method handleProxy: " + handleProxy);
        // System.out.println("Relay method deserializeCode: " + deserializeCode);
        // System.out.println("Relay method invocation: " + invocation);
        /**
         * Static method means there is no associated entry in mirror object registry
         */
        if (isStatic) {
            invocation = className + "." + methodName + callingParams + semiColon;
        } else {
            invocation = transCast + "." + methodName + callingParams + semiColon;
        }

        if (retType.equals("void")) {
            return "{" + handleMirror + handleProxy + deserializeCode + invocation + "}";
        } else {
            invocation = sendRelayReturn(retType, className, invocation, transPrefix, isStatic);
            return "{" + handleMirror + handleProxy + deserializeCode + invocation + "}";
        }

    }

    /**
     * Add graal centrypoint annotation to method.To prevent overwriting previous
     * class or method annotations, we first get the present annotations and add the
     * new one to the former if it exists.
     */
    public void addGraalAnnotation(CtClass cls, CtMethod relayMethod) throws Exception {
        final ClassFile cf = cls.getClassFile();
        MethodInfo minfo = relayMethod.getMethodInfo();
        AnnotationsAttribute attrib = (AnnotationsAttribute) minfo.getAttribute(AnnotationsAttribute.visibleTag);

        ConstPool cp = minfo.getConstPool();
        String graalName = relayMethod.getName();

        if (attrib == null) {
            attrib = new AnnotationsAttribute(cp, AnnotationsAttribute.visibleTag);
        }

        // create annotation
        Annotation annot = new Annotation(graalEntryPoint, cp);
        annot.addMemberValue("name", new StringMemberValue(graalName, cp));

        // create CEntryPoint options
        Annotation cOptions = new Annotation(cEntryPointOptions, cp);
        cOptions.addMemberValue("include", new ClassMemberValue(doNotInclude, cp));

        attrib.addAnnotation(annot);
        /**
         * We should not include secure relay entrypoints automatically b/c this will
         * make all class methods reachable after analysis. This will lead to a larger
         * TCB after partitioning. These entrypoints will be added dynamically with a
         * Feature class during static analysis.
         */

        if (this.isTrusted) {
            //attrib.addAnnotation(cOptions);
            //System.out.println("adding centrypoint options -------------------------------->>>>>>");

        }
        // cf.addAttribute(graalAnnotationsAttrib);
        // cf.setVersionToJava5();

        // add annotation to relay method
        relayMethod.getMethodInfo().addAttribute(attrib);

    }

    /**
     * Add sgx security info annotation to method. To prevent overwriting previous
     * class or method annotations, we first get the present annotations and add the
     * new one to the former if it exists.
     */
    public void addSgxAnnotation(CtClass cls, CtMethod relayMethod, boolean isConstructor) throws Exception {
        final ClassFile cf = cls.getClassFile();
        MethodInfo minfo = relayMethod.getMethodInfo();
        AnnotationsAttribute attrib = (AnnotationsAttribute) minfo.getAttribute(AnnotationsAttribute.visibleTag);

        ConstPool cp = minfo.getConstPool();
        String transitionType = this.isTrusted ? "ecall" : "ocall";

        if (attrib == null) {
            attrib = new AnnotationsAttribute(cp, AnnotationsAttribute.visibleTag);
        }

        // create annotation
        Annotation annot = new Annotation(sgxSecurityInfo, cp);
        annot.addMemberValue("transition", new StringMemberValue(transitionType, cp));
        /**
         * This extra annotation will be used by the SGXProxyGenerator at the level of
         * graal during EDL generation.
         */
        if (isConstructor) {
            annot.addMemberValue("type", new StringMemberValue("relay_constr", cp));
        }
        attrib.setAnnotation(annot);
        // cf.addAttribute(sgxAnnotationsAttrib);
        // cf.setVersionToJava5();

        // add annotation to relay method
        relayMethod.getMethodInfo().addAttribute(attrib);

    }

    /**
     * Add graal CFunction annotation to a native method.
     */
    static void addCFuncAnnotation(CtMethod nativeMethod) throws Exception {

        MethodInfo minfo = nativeMethod.getMethodInfo();
        AnnotationsAttribute attrib = (AnnotationsAttribute) minfo.getAttribute(AnnotationsAttribute.visibleTag);

        ConstPool cp = minfo.getConstPool();

        if (attrib == null) {
            attrib = new AnnotationsAttribute(cp, AnnotationsAttribute.visibleTag);
        }

        // create annotation
        Annotation annot = new Annotation(cFunction, cp);
        annot.addMemberValue("value", new StringMemberValue(nativeMethod.getName(), cp));
        attrib.setAnnotation(annot);

        // add annotation to relay method
        nativeMethod.getMethodInfo().addAttribute(attrib);

    }

    /**
     * Returns the non-qualified name: i.e the substring after the last '.' : usage:
     * getting short class names from the fully-qualified variant.
     */
    static String getSimpleName(String longName) {
        int lastDot = longName.lastIndexOf('.');
        if (lastDot <= 0) {
            return longName;
        } else {
            return longName.substring(lastDot + 1).trim();
        }

    }

    /**
     * This method converts the associated method params in @param mParams into the
     * associated CtClass type for all primitive types. For object types, the
     * associated new type will be a CCharPointer followed by an int which will
     * represent the length of the serialized object. The new params are written
     * to @param newParams .
     */
    public void setRelayParams(ArrayList<String> newParams, CtClass[] mParams) {

        for (int i = 0; i < mParams.length; i++) {
            newParams.add(getRelayType(mParams[i].getName()));
        }
    }

    /**
     * Creates a string which represents the exact parameters as they will appear in
     * the final relay method: For example: (IsolateTthread param1, int param2,
     * ....)
     */

    static String getRelayParams(CtClass[] mParams, CtClass cls, boolean isConstructor) {
        /**
         * The first parameter of a graal entrypoint needs to be a graal isolate thread.
         * For our relay methods, the second parameter will be the hashcode of the
         * calling proxy object in the opposite runtime. For each non object parameter,
         * a graal CCharPointer is used, and the following param is the length of the
         * char/byte buffer.
         */
        String relayType;
        String realType;
        String className = cls.getName();
        String relayParams;
        int i;
        // constructors will not have return buffer parameters
        if (isConstructor) {
            relayParams = "(" + isoThread + space + "param1" + comma + "int param2";
            i = 3;

        } else {
            relayParams = "(" + isoThread + space + "param1" + comma + "int param2" + comma + ccharpointer + space
                    + "retPtr" + comma + "int len";
            i = 5;
        }

        for (int j = 0; j < mParams.length; j++) {
            realType = mParams[j].getName();
            relayType = getRelayType(realType);
            // add an int length param next to all char* types
            if (hasObject(relayType)) {

                OBJTYPE objType = getObjectType(realType, className);

                switch (objType) {
                    case PROXY:
                        /** Pass only the id's of proxy objects */
                        relayParams += comma + "int" + space + "param" + i;
                        i++;
                        break;

                    case MIRROR:
                        /** Pass only the id's of proxy objects */
                        relayParams += comma + "int" + space + "param" + i;
                        i++;
                        break;

                    case DONTCARE:

                        relayParams += comma + relayType + space + "param" + i + comma + "int" + space + "param"
                                + (i + 1);
                        i += 2;
                        break;

                    default:
                        break;
                }

            } else {
                relayParams += comma + relayType + space + "param" + i;
                i++;
            }

            // System.out.println("Relay param name: " +
            // getRelayType(mParams[j].getName()));
        }
        // Close the parantheses
        relayParams += ")";

        return relayParams;

    }

    /**
     * Returns the appropriate java type (as a string) corresponding to the input
     * type, to be used in relay methods which are graal entrypoints. The latter do
     * not support object params. For non primitive types return graal CCharpointer
     * type
     */
    static String getRelayType(String type) {

        String ret = null;
        switch (type) {
            case "boolean":
            case "byte":
            case "char":
            case "short":
            case "int":
            case "long":
            case "float":
            case "double":
            case "void":
            case isoThread:
                return type;

            default:
                // The type is not a primitive type, so must be an object type. Use ccharpointer
                // TODO: add other tests
                return ccharpointer;

        }
        // return ret;

    }

    /**
     * Tests for object types following the same rule applied in getType method.
     * 
     * @param type
     * @return
     */
    static boolean hasObject(String type) {
        if (type.equals(ccharpointer)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns code to resolve return value of proxy method. For serializable object
     * returns, we get the corresponding pointer from the returnObjects map and the
     * returned length of the byte array, deserialize the byte array, and
     * reconstruct the object to be returned.We then remove the returned pointer
     * from the map. For proxy return types, return the corresponding mirror object.
     * 
     * @param retType
     * @param className
     * @param enclaveTrans
     * @param isStatic
     * @return
     */

    static String resolveProxyReturn(String retType, String className, String enclaveTrans, boolean isStatic) {

        String ret = "";
        // TODO: change hash for static calls else all static calls will have same key

        String retHash = isStatic ? "0" : "$0.proxyHash";
        String transition = "";

        // Test return type
        String relayType = getRelayType(retType);
        if (hasObject(relayType)) {
            OBJTYPE objType = getObjectType(retType, className);

            switch (objType) {
                case PROXY:
                    // TODO - easy
                    break;

                case MIRROR:
                    // TODO - hard
                    break;

                case DONTCARE:

                    ret += "int retLen = " + enclaveTrans + semiColon;
                    // method will return size of serialized buffer at the opposite RT
                    ret += "byte[] buf = new byte[retLen];";
                    // copy the necessary num of bytes from the return buffer
                    ret += arrayCopy + "(buf,retBuf,retLen);";
                    // deserialize the copied bytes to recreate the return object
                    ret += retType + space + "retObj" + space + "=" + space + "(" + retType + ")" + sgxDeserialize
                            + "(buf);";
                    ret += "if(retObj == null){System.out.println(\"Return object in proxy method is null: ret size = \"+retLen);}";

                    ret += "return retObj;";
                    break;

                default:
                    break;
            }

        } else {
            // primitive return type
            ret = "return" + space + enclaveTrans;
        }
        return ret;
    }

    /**
     * Returns code to handle return value for relay method. Serializable object
     * returns will be serialized and sent to the opposite RT via an enclave
     * transition. The corresponding ccharpointer will be added to the returnObjects
     * hashmap in the opposite RT. The length of the serialized byte array will be
     * returned. For return objects which are proxies, we send the hash of the proxy
     * and use the mirror at the other end.
     * 
     * @param retType
     * @param className
     * @param invocation
     * @param isStatic
     * @return
     */

    static String sendRelayReturn(String retType, String className, String invocation, String transPrefix,
            boolean isStatic) {
        String ret = "";
        String retHash = isStatic ? "0" : "param2";
        // String transition = "";

        // Test return type
        String relayType = getRelayType(retType);
        if (hasObject(relayType)) {
            OBJTYPE objType = getObjectType(retType, className);

            switch (objType) {
                case PROXY:
                    // TODO - easy
                    break;

                case MIRROR:
                    // TODO - hard
                    break;

                case DONTCARE:
                    // call mirror-method to return object
                    ret += "Object retObj = " + invocation + semiColon;

                    // ret += retType + " ret = (" + retType + ")retObj;";//test: OK
                    // ret += "System.out.println(\"Unreturned return: \"+ret);"; //test: OK
                    // serialize returned object
                    ret += "byte[] retBytes" + space + "=" + space + sgxSerialize + "(retObj);";
                    ret += "int retLen" + space + "=" + space + "retBytes.length;";
                    // copy these bytes to input ccharpointer buffer
                    ret += "byte[] tempBuf = " + getByteBuffer + "(retPtr," + BUFSIZ + ");";
                    ret += arrayCopy + "(tempBuf,retBytes,retLen);";
                    // ret += zeroFill + "(tempBuf,retLen);";

                    // ret += "retPtr = " + getCharPointer + "(retBytes);";
                    ret += "return retLen;";
                    break;

                default:
                    break;
            }

        } else {
            // primitive return type
            ret = "return" + space + invocation;
        }
        return ret;
    }

    /**
     * Returns code (as string) to perform object parameter serialization.
     * 
     * @param paramIndex
     * @return
     */
    static String serializeParam(int paramIndex) {
        String serializeCode = "";
        serializeCode += "Object obj" + paramIndex + space + "=" + space + "$" + (paramIndex + 1) + semiColon;
        serializeCode += "byte[] bytes" + paramIndex + space + "=" + space + sgxSerialize + "(obj" + paramIndex + ");";
        serializeCode += ccharpointer + space + "buffer" + paramIndex + space + "=" + space + getCharPointer + "(bytes"
                + paramIndex + ");";
        serializeCode += "int len" + paramIndex + space + "=" + space + "bytes" + paramIndex + ".length;";
        return serializeCode;
    }

    /**
     * Returns code (as string) to perform object parameter deserialization.
     * 
     * @param paramIndex
     * @param typeName
     * @return
     */
    static String deserializeParam(int paramIndex, String typeName) {
        String deserializeCode = "";
        deserializeCode += "byte[] bytes" + paramIndex + space + "=" + space + getByteBuffer + "(param" + paramIndex
                + comma + "param" + (paramIndex + 1) + ");";
        deserializeCode += typeName + space + "obj" + paramIndex + space + "=" + space + "(" + typeName + ")"
                + sgxDeserialize + "(bytes" + paramIndex + ");";

        return deserializeCode;
    }

    /**
     * Returns code (as string) for handling proxy object parameters in strippped
     * methods.
     * 
     * @param paramIndex
     * @param typeName
     * @return
     */
    static String sendProxy(int paramIndex, String typeName) {
        /**
         * Example: Proxy proxyi = (Proxy)$(i+1); int proxyHashi = proxyi.proxyHash;
         */
        String code = "";
        code += typeName + space + "proxy" + paramIndex + space + "=" + space + "(" + typeName + ")" + "$"
                + (paramIndex + 1) + semiColon;
        // error test
        // code += "int proxyHash" + paramIndex + " = 11;";

        // manual hash: proxyHash field may not be available at this point
        String getHash = hashObject + "(proxy" + paramIndex + ");";

        // code += "int" + space + "proxyHash" + paramIndex + space + "=" + space +
        // "proxy" + paramIndex + ".proxyHash;";
        code += "int" + space + "proxyHash" + paramIndex + space + "=" + space + getHash;

        // System.out.println("Send proxy code: " + code);

        return code;

    }

    /**
     * Returns code (as string) for resolving proxy object parameters in relay
     * methods.
     * 
     * @param paramIndex
     * @param typeName
     * @return
     */
    static String resolveProxy(int paramIndex, String typeName) {
        String code = "";
        code += typeName + space + "obj" + paramIndex + space + "=" + space + "(" + typeName + ")" + sgxObjTrans
                + ".getMirrorObject(param" + paramIndex + ");";
        return code;
    }

    /**
     * Returns code to handle mirror objects to be sent across the enclave boundary.
     * If object is a mirror object, get the corresponding proxy hash and send. If
     * it is not a mirror object, create a proxy object at the other end and add
     * this param object as its mirror.
     * 
     * @param paramIndex
     * @param typeName
     * @return
     */
    static String sendMirror(int paramIndex, String paramType, CtClass cls, String transitionType) throws Exception {

        String code = "int proxyHash" + paramIndex + " = 0;";
        code += "int hash = " + getProxyHash + "(" + "$" + (paramIndex + 1) + ");";
        // String setProxyHash = "proxyHash" + paramIndex + space + "=" + space +
        // getProxyHash + "(" + "$"
        // + (paramIndex + 1) + ");";
        // code += "isMirror = " + isMirrorObj + "(" + "$" + (paramIndex + 1) + ");";
        // code += "if(isMirror){" + setProxyHash + "}";

        // NB:-123456 is a tentative magic number for impossible hashes
        code += "if(hash != -123456){proxyHash" + paramIndex + " = hash;System.out.println(\"Proxy hash found\");}";

        /** Create proxy object in enclave transition */
        String createProxy = createProxy(paramType, paramIndex, cls, transitionType);

        /** Add mirror object to sgx translator mirror object registry */
        String registerMirror = sgxObjTrans + ".putMirrorObject(proxyHash" + paramIndex + comma + "$" + (paramIndex + 1)
                + ");";

        code += "else {" + createProxy + registerMirror
                + "System.out.println(\"Proxy hash not found:created dynamic proxy:\"+proxyHash0);}";
        // test
        // code = "System.out.println(\"xxxxxxxx\");";
        // code += createProxy + registerMirror;

        // System.out.println("Send mirror code: " + code);
        return code;
    }

    static String createProxy(String paramType, int paramIndex, CtClass cls, String transitionType) throws Exception {
        // add native transition to create proxy
        String cname = getSimpleName(paramType);
        addNativeOverload(cls, paramType, transitionType);
        String code = "";// getCurIso;
        // we use the overloaded constructor to build the proxy
        code += "proxyHash" + paramIndex + " = " + transitionType + "_overload_" + cname + "(iso);";

        return code;

    }

    /**
     * Returns code to resolve associated proxies for mirror object params sent
     * across the encalve boundary.
     */
    static String resolveMirror(int paramIndex, String paramType) throws Exception {

        String code = "";
        code += paramType + space + "obj" + paramIndex + space + "=" + space + "(" + paramType + ")" + getProxy
                + "(param" + paramIndex + ");";
        return code;
    }

    /**
     * Returns object type from the typeName and image security family
     * 
     * @param typeName
     * @param paramIndex
     * @param isTrusted
     * @return
     */
    static OBJTYPE getObjectType(String paramType, String className) {

        OBJTYPE ret = OBJTYPE.DONTCARE;// default

        // test object parameter security family
        boolean secObjClass = trustedClasses.contains(paramType);
        boolean unsecObjClass = untrustedClasses.contains(paramType);
        // test parent class security family
        boolean secClass = trustedClasses.contains(className);
        boolean unsecClass = untrustedClasses.contains(className);

        /**
         * Parameter is a proxy type if it belongs to the same security family as the
         * parent class
         */
        boolean proxy = (secClass && secObjClass) || (unsecClass && unsecObjClass);

        /**
         * Parameter is a don't care type if it is unannotated-i.e it neither trusted
         * nor untrusted
         */
        boolean dontCare = !secObjClass && !unsecObjClass;

        /**
         * Parameter is a mirror or simply a concrete object of an annotated class. This
         * occurs when the class being instrumented is of opposite security family to
         * the param. Here we register this object as a mirror object if it is not, and
         * we create or use the corresponding proxy object at the other end as parameter
         * return
         */
        boolean mirror = (secClass && unsecObjClass) || (unsecClass && secObjClass);

        if (dontCare) {
            // default: don't care class
        } else if (proxy) {
            ret = OBJTYPE.PROXY;
        } else if (mirror) {
            ret = OBJTYPE.MIRROR;
        }

        return ret;
    }

    /** Returns ctclass object corresponding to the class name passed. */
    public CtClass getCtClass(String cname) {

        return (this.cpool.makeClass(cname));
    }

    /**
     * Create custom class loader for each security family. This controls the
     * visibility of the class files (same copies) for trusted and untrusted class
     * instrumentation.
     */
    public synchronized ClassLoader getCLoader(boolean security, String basePath) {
        /**
         * Class search path: for trusted image instrumentation classes will be searched
         * in the trusted subdirector and for untrusted image instrumentation classes
         * will be searched in the untrusted subdirectory.
         */

        String cpath = basePath;

        if (security) {
            cpath += "/trusted";
        } else {
            cpath += "/untrusted";
        }

        List<String> paths = Arrays.asList(cpath);
        URL[] urls = paths.stream().map(path -> {
            File file = new File(path);

            try {
                return file.toURI().toURL();
            } catch (MalformedURLException e) {
                throw new IllegalStateException(e);

            }

        }).toArray(URL[]::new);

        return new URLClassLoader(urls, this.getClass().getClassLoader());
    }

    static void printAnnotatedClass() {
        System.out.println("---------------------- trusted Class List ------------------------");
        for (String cname : trustedClasses) {
            System.out.println(cname);
        }

        System.out.println("---------------------- Untrusted Class List ----------------------");
        for (String cname : untrustedClasses) {
            System.out.println(cname);
        }

    }

    static boolean isMainMethod(CtMethod m) {
        return m.getName().equals("main");

    }

    /**
     * Returns relative path for parent dir of a given file name Ex: com/util/Name
     * --> /com/util
     * 
     * @param fileName
     * @return
     */
    static String getParentDir(String fileName) {
        final int lastPointPos = fileName.lastIndexOf('/');
        if (lastPointPos <= 0) {
            return "/" + fileName;
        } else {
            return "/" + fileName.substring(0, lastPointPos);
        }
    }

    /**
     * Registers the class to serializable class list. These will be added to the
     * serialization config file generated by the native image agent.
     * 
     * @param className
     */
    static void registerSerializable(String className) {

        if (!serializedClasses.contains(className)) {
            serializedClasses.add(className);
        }

    }

    public static void main(String[] args) {
        String dir = null;
        // NB: this is no longer needed: to be removed
        String pkgName = null;

        /** Parse arguments to obtain app package name and jtransformer dir path */

        if (args.length != 2) {
            System.out.println("Wrong cmd line args: specify jtransformer dir");
        } else {
            dir = args[0];
            pkgName = args[1];
            System.out.println("Dir name: " + dir + " Package name: " + pkgName);
        }

        assert (dir != null || pkgName != null) : "provide valid dir and pkg names";

        // These two can be done on separate threads in a thread safe way.
        Object trustedTransformer = new JAssistClassTransformer(dir, pkgName, true);

        try {
            ((JAssistClassTransformer) trustedTransformer).transformClasses();

        } catch (Exception e) {
            e.getStackTrace();
        }

        JAssistClassTransformer untrustedTransformer = new JAssistClassTransformer(dir, pkgName, false);
        try {

            untrustedTransformer.transformClasses();

        } catch (Exception e) {
            e.getStackTrace();
        }

        /** Add serializable classes to serialization config */
        AgentHelper.addClasses(serializedClasses);
    }

}