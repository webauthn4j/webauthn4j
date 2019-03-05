/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.response.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * List of supported extensions as an array of extension identifier strings.
 * @see <a href="https://www.w3.org/TR/webauthn-1/#ref-for-typedefdef-authenticationextensionssupported">§10.5. Supported Extensions Extension (exts) - Client extension output</a>
 */
public class AuthenticationExtensionsSupported extends AbstractList<String> implements Serializable {

    private String[] extensions;
    private final int size;

    @JsonCreator
    public AuthenticationExtensionsSupported(List<String> extensions){
        AssertUtil.notNull(extensions, "extensions must not be null");
        this.size = extensions.size();
        this.extensions = extensions.toArray(new String[this.size]);
    }

    @Override
    public String get(int index) {
        return extensions[index];
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AuthenticationExtensionsSupported strings = (AuthenticationExtensionsSupported) o;
        return size == strings.size &&
                Arrays.equals(extensions, strings.extensions);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), size);
        result = 31 * result + Arrays.hashCode(extensions);
        return result;
    }
}