/*
 * Copyright (c) 2018, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or
 * data (collectively the "Software"), free of charge and under any and all
 * copyright rights in the Software, and any and all patent rights owned or
 * freely licensable by each licensor hereunder covering either (i) the
 * unmodified Software as contributed to or provided by such licensor, or (ii)
 * the Larger Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at a
 * minimum a reference to the UPL must be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.oracle.truffle.api.library;

import com.oracle.truffle.api.dsl.GeneratedBy;
import com.oracle.truffle.api.library.LibraryFactory.ResolvedDispatch;
import com.oracle.truffle.api.utilities.FinalBitSet;

/**
 * Base class for generated export classes. This class is not intended to be sub-classed or used
 * manually.
 *
 * @see ExportLibrary to implement / export library message.
 * @since 19.0
 */
public abstract class LibraryExport<T extends Library> {

    static final String GENERATED_CLASS_SUFFIX = "Gen";

    private final Class<?> receiverClass;
    private final Class<? extends T> library;
    private final boolean defaultExport;

    Class<?> registerClass;

    /**
     * Constructor for generated code. Do not call manually.
     *
     * @since 19.0
     */
    protected LibraryExport(Class<? extends T> library, Class<?> receiverClass, boolean defaultExport) {
        this.library = library;
        this.receiverClass = receiverClass;
        this.defaultExport = defaultExport;
    }

    /**
     * Implemented generated by {@link ExportLibrary}. Do not implement manually.
     *
     * @since 19.0
     */
    protected abstract T createUncached(Object receiver);

    /**
     * Implemented generated by {@link ExportLibrary}. Do not implement manually.
     *
     * @since 19.0
     */
    protected abstract T createCached(Object receiver);

    final boolean isDefaultExport() {
        return defaultExport;
    }

    final Class<?> getReceiverClass() {
        return receiverClass;
    }

    final Class<? extends T> getLibrary() {
        return library;
    }

    /**
     * Internal method for generated code only.
     *
     * @since 20.0
     */
    protected static <T extends Library> T createDelegate(LibraryFactory<T> factory, T delegate) {
        T parent = factory.createDelegate(delegate);
        if (!delegate.isAdoptable()) {
            /*
             * We force adoption for the uncached case because we need the parent pointer to
             * implement @CachedLibrary("this"), as this should point to the parent delgate library.
             * With this we can use the same parent pointer approach for cached and uncached.
             */
            LibraryAccessor.nodeAccessor().forceAdoption(parent, delegate);
        }
        return parent;
    }

    /**
     * Internal method for generated code only.
     *
     * @since 20.0
     */
    protected static FinalBitSet createMessageBitSet(LibraryFactory<?> factory, String... messageNames) {
        Message[] messages = new Message[messageNames.length];
        for (int i = 0; i < messageNames.length; i++) {
            messages[i] = factory.nameToMessages.get(messageNames[i]);
        }
        return factory.createMessageBitSet(messages);
    }

    /**
     * {@inheritDoc}
     *
     * @since 19.0
     */
    @Override
    public final String toString() {
        return "LibraryExport[" + this.getClass().getAnnotation(GeneratedBy.class).value().getName() + "]";
    }

    /**
     * Called only by code generated by {@link ExportLibrary}. Do not call manually. Multiple calls
     * with the same receiver class will lead to an {@link IllegalStateException}.
     *
     * @since 19.0
     */
    public static <T extends Library> void register(Class<?> receiverClass, LibraryExport<?>... libs) {
        ResolvedDispatch.register(receiverClass, libs);
    }

    /**
     * Internal interface for generated code only.
     *
     * @since 20.0
     */
    protected interface DelegateExport {

        /**
         * Internal method for generated code only.
         *
         * @since 20.0
         */
        Object readDelegateExport(Object receiver);

        /**
         * Internal method for generated code only.
         *
         * @since 20.0
         */
        FinalBitSet getDelegateExportMessages();

        /**
         * Internal method for generated code only.
         *
         * @since 20.0
         */
        Library getDelegateExportLibrary(Object delegate);

    }

}