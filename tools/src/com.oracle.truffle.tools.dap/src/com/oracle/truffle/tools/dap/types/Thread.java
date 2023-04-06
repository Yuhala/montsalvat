/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.oracle.truffle.tools.dap.types;

import com.oracle.truffle.tools.utils.json.JSONObject;
import java.util.Objects;

/**
 * A Thread.
 */
public class Thread extends JSONBase {

    Thread(JSONObject jsonData) {
        super(jsonData);
    }

    /**
     * Unique identifier for the thread.
     */
    public int getId() {
        return jsonData.getInt("id");
    }

    public Thread setId(int id) {
        jsonData.put("id", id);
        return this;
    }

    /**
     * A name of the thread.
     */
    public String getName() {
        return jsonData.getString("name");
    }

    public Thread setName(String name) {
        jsonData.put("name", name);
        return this;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (this.getClass() != obj.getClass()) {
            return false;
        }
        Thread other = (Thread) obj;
        if (this.getId() != other.getId()) {
            return false;
        }
        if (!Objects.equals(this.getName(), other.getName())) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 79 * hash + Integer.hashCode(this.getId());
        hash = 79 * hash + Objects.hashCode(this.getName());
        return hash;
    }

    public static Thread create(Integer id, String name) {
        final JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("name", name);
        return new Thread(json);
    }
}
