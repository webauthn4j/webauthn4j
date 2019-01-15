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

package com.webauthn4j.extras.fido.metadata;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.webauthn4j.validator.exception.CertificateException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

import java.nio.charset.StandardCharsets;

/**
 * Test for CertPathJWSVerifier
 */
public class CertPathJWSVerifierTest {

    private CertPathJWSVerifier target;

    @Before
    public void setup() {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        target = new CertPathJWSVerifier(resourceLoader);
    }

    @Test(expected = CertificateException.class)
    public void verify_test_with_outdatedToken() throws Exception {
        Resource resource = new ClassPathResource("com/webauthn4j/extras/fido/metadata/token.txt");
        String token = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        SignedJWT jwt = (SignedJWT) JWTParser.parse(token);
        target.verify(jwt);
    }
}
