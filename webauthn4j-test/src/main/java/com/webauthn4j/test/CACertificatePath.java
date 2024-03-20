/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.test;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AssertUtil;

import java.security.cert.X509Certificate;
import java.util.*;

public class CACertificatePath extends AbstractList<X509Certificate> {

    private final int size;
    private final X509Certificate[] certificates;

    @JsonCreator
    public CACertificatePath(List<X509Certificate> certificates) {
        AssertUtil.notNull(certificates, "certificates must not be null");
        this.size = certificates.size();
        this.certificates = certificates.toArray(new X509Certificate[this.size]);
    }

    public CACertificatePath() {
        this(Collections.emptyList());
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public X509Certificate get(int index) {
        return certificates[index];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CACertificatePath that = (CACertificatePath) o;
        return size == that.size &&
                Arrays.equals(certificates, that.certificates);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), size);
        result = 31 * result + Arrays.hashCode(certificates);
        return result;
    }
}
