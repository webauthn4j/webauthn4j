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

import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class WebAuthnTrustAnchorServiceImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Mock
    private TrustAnchorProvider trustAnchorProvider;

    @InjectMocks
    private WebAuthnTrustAnchorServiceImpl target;

    @Test
    public void getTrustAnchors_test() {
        Set<TrustAnchor> trustAnchorsA = target.getTrustAnchors();
        Set<TrustAnchor> trustAnchorsB = target.getTrustAnchors();

        assertThat(trustAnchorsA).isEqualTo(trustAnchorsB);

        verify(trustAnchorProvider, times(1)).provide();
    }
}
