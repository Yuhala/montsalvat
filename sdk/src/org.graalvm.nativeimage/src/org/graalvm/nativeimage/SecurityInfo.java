/*
 * Created on Mon Sep 07 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

package org.graalvm.nativeimage;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
//import com.oracle.svm.core.annotate.NeverInline;

/**
 * Annotation used for SGX security metadata. Trusted methods/types have
 * security() = "trusted" and untrusted methods/types have security() =
 * "trusted".
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD, ElementType.FIELD })
// @NeverInline("do not inline sgx transition routine")
public @interface SecurityInfo {
    /**
     * 
     * @return Specifies whether the class is trusted or not trusted classes will be
     *         linked only to trusted code Untrusted classes will be linked only to
     *         untrusted code
     */
    public String security() default "none";
    // Values:  Trusted, Untrusted

    /**
     * 
     * @return Specifies accessibility for methods and fields. all: method or
     *         attribute accessible by trusted and untrusted RTs (accessed via an
     *         ocall or ecall). in: method or attribute accessible to trusted RT
     *         only. out: method or attribute accessible to untrusted RT only
     */
    public String access() default "all";

    /**
     * Specifies the transition type for a given method: ecalls/enclave methods that
     * will be called by the untrusted code have transition = ecall and
     * ocalls/untrusted methods which will be called from the enclave have
     * transition = ocall.
     */
    public String transition() default "none";

    /**
     * Specifies if an isolate should be generated to serve as execution context, or
     * not. In the latter case, the default isolate thread for the specific runtime
     * (enclave or untrusted runtime) will be used as execution context.
     */
    public boolean gen_iso() default false;

    /**
     * Specifies the type of a specific element: relay method (relay_method), relay
     * constructor (relay_constr) etc
     */
    public String type() default "relay_method";

    /** Specifies whether or not to add transparent encryption on a field/method. */
    public boolean encrypt() default false;
}