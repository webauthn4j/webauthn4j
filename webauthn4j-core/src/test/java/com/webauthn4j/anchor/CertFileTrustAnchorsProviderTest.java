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

package com.webauthn4j.anchor;


import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CertFileTrustAnchorsProviderTest {

    private CertFileTrustAnchorsProvider target;

    @Test
    void provide_test() throws Exception {
        target = new CertFileTrustAnchorsProvider();
        Path path = Paths.get(ClassLoader.getSystemResource("com/webauthn4j/anchor/CertFileTrustAnchorsProviderTest/test.crt").toURI());
        target.setCertificates(Collections.singletonList(path));

        Map<AAGUID, Set<TrustAnchor>> trustAnchors = target.provide();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void provide_test_with_invalid_path() {
        target = new CertFileTrustAnchorsProvider(Collections.singletonList(Paths.get("invalid.path.to.crt")));

        assertThrows(UncheckedIOException.class,
                () -> target.provide()
        );
    }

    @Test
    void getter_setter_test() throws Exception {
        target = new CertFileTrustAnchorsProvider();
        List<Path> paths = Collections.singletonList(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/anchor/CertFileTrustAnchorsProviderTest/test.crt").toURI()));
        target.setCertificates(paths);
        assertThat(target.getCertificates()).isEqualTo(paths);
    }

}