/*
 * Created on Mon Nov 09 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

package com.oracle.svm.hosted.c.codegen;

import static com.oracle.svm.core.util.VMError.shouldNotReachHere;
import static com.oracle.svm.hosted.NativeImageOptions.CStandards.C11;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.graalvm.nativeimage.Platform;
import org.graalvm.nativeimage.c.function.CFunctionPointer;
import org.graalvm.nativeimage.c.function.InvokeCFunctionPointer;
import org.graalvm.word.SignedWord;
import org.graalvm.word.UnsignedWord;

import com.oracle.svm.core.util.InterruptImageBuilding;
import com.oracle.svm.core.util.UserError;
import com.oracle.svm.core.util.VMError;
import com.oracle.svm.hosted.NativeImageOptions;
import com.oracle.svm.hosted.NativeImageOptions.CStandards;
import com.oracle.svm.hosted.c.NativeLibraries;
import com.oracle.svm.hosted.c.info.ElementInfo;
import com.oracle.svm.hosted.c.info.EnumInfo;
import com.oracle.svm.hosted.c.info.InfoTreeBuilder;
import com.oracle.svm.hosted.c.info.PointerToInfo;
import com.oracle.svm.hosted.c.info.StructInfo;

import jdk.vm.ci.meta.JavaKind;
import jdk.vm.ci.meta.MetaAccessProvider;
import jdk.vm.ci.meta.ResolvedJavaMethod;
import jdk.vm.ci.meta.ResolvedJavaType;

/**
 * Some methods of the CSourceCodeWriter had to be modified to write sgx proxies
 * correctly. Best solution was to create a child class and redefine those
 * methods. PYuhala
 */
public class SGXProxyWriter extends CSourceCodeWriter {

    public SGXProxyWriter(Path dir) {
        super(dir);
    }

    public static String toCTypeName(ResolvedJavaMethod method, ResolvedJavaType type, Optional<String> useSiteTypedef,
            boolean isConst, boolean isUnsigned, MetaAccessProvider metaAccess, NativeLibraries nativeLibs) {
        boolean isNumericInteger = type.getJavaKind().isNumericInteger();
        UserError.guarantee(isNumericInteger || !isUnsigned,
                "Only integer types can be unsigned. %s is not an integer type in %s", type, method);

        if (metaAccess == null) {
            System.out.println("metaaccess is null ----------------------------------->");
        }
        boolean isUnsignedWord = metaAccess.lookupJavaType(UnsignedWord.class).isAssignableFrom(type);
        boolean isSignedWord = metaAccess.lookupJavaType(SignedWord.class).isAssignableFrom(type);
        boolean isWord = isUnsignedWord || isSignedWord;
        boolean isObject = type.getJavaKind() == JavaKind.Object && !isWord;
        UserError.guarantee(isObject || !isConst,
                "Only pointer types can be const. %s in method %s is not a pointer type.", type, method);

        if (useSiteTypedef != null && useSiteTypedef.isPresent()) {
            return (isConst ? "const " : "") + useSiteTypedef.get();
        } else if (isNumericInteger) {
            return toCIntegerType(type, isUnsigned);
        } else if (isUnsignedWord) {
            return "size_t";
        } else if (isSignedWord) {
            return "ssize_t";
        } else if (isObject) {
            return (isConst ? "const " : "") + cTypeForObject(type, metaAccess, nativeLibs);
        } else {
            switch (type.getJavaKind()) {
                case Double:
                    return "double";
                case Float:
                    return "float";
                case Void:
                    return "void";
                default:
                    throw shouldNotReachHere();
            }
        }
    }

    private static String cTypeForObject(ResolvedJavaType type, MetaAccessProvider metaAccess,
            NativeLibraries nativeLibs) {
        ElementInfo elementInfo = nativeLibs.findElementInfo(type);
        if (elementInfo instanceof PointerToInfo) {
            PointerToInfo pointerToInfo = (PointerToInfo) elementInfo;
            return (pointerToInfo.getTypedefName() != null ? pointerToInfo.getTypedefName()
                    : pointerToInfo.getName() + "*");
        } else if (elementInfo instanceof StructInfo) {
            StructInfo structInfo = (StructInfo) elementInfo;
            return structInfo.getTypedefName() != null ? structInfo.getTypedefName() : structInfo.getName() + "*";
        } else if (elementInfo instanceof EnumInfo) {
            return elementInfo.getName();
        } else if (isFunctionPointer(metaAccess, type)) {
            return InfoTreeBuilder.getTypedefName(type) != null ? InfoTreeBuilder.getTypedefName(type) : "void *";
        }
        return "void *";
    }

    private static String toCIntegerType(ResolvedJavaType type, boolean isUnsigned) {
        boolean c11Compatible = NativeImageOptions.getCStandard().compatibleWith(C11);
        String prefix = "";
        if (isUnsigned) {
            prefix = c11Compatible ? "u" : "unsigned ";
        }
        switch (type.getJavaKind()) {
            case Boolean:
                if (NativeImageOptions.getCStandard().compatibleWith(CStandards.C99)) {
                    return "bool";
                } else {
                    return "int";
                }
            case Byte:
                return prefix + (c11Compatible ? "int8_t" : "char");
            case Char:
                return prefix + (c11Compatible ? "int16_t" : "short");
            case Short:
                return prefix + (c11Compatible ? "int16_t" : "short");
            case Int:
                return prefix + (c11Compatible ? "int32_t" : "int");
            case Long:
            return prefix + (c11Compatible ? "int64_t" : "long");
                //pyuhala: changed because sgx edl does not recognise long long int
                //return prefix + (c11Compatible ? "int64_t" : "long long int");
        }
        throw VMError.shouldNotReachHere("All integer types should be covered. Got " + type.getJavaKind());
    }

    private static boolean isFunctionPointer(MetaAccessProvider metaAccess, ResolvedJavaType type) {
        boolean functionPointer = metaAccess.lookupJavaType(CFunctionPointer.class).isAssignableFrom(type);
        return functionPointer && Arrays.stream(type.getDeclaredMethods())
                .anyMatch(v -> v.getDeclaredAnnotation(InvokeCFunctionPointer.class) != null);
    }

}
