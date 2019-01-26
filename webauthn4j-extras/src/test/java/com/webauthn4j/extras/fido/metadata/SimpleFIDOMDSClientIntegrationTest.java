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

import org.junit.Before;
import org.junit.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for SimpleFIDOMDSClient
 */
public class SimpleFIDOMDSClientIntegrationTest {

    private SimpleFIDOMDSClient target;

    @Before
    public void setup() {
        target = new SimpleFIDOMDSClient();
    }

    @Test
    public void retrieveMetadataTOC_test() {
        String metadataTOC = target.fetchMetadataTOC();
        assertThat(metadataTOC).isNotNull();
    }

    @Test
    public void retrieveMetadataStatement_test() {
        String url = "https://mds.fidoalliance.org/metadata/4e4e%23400a";
        String metadataStatement = target.fetchMetadataStatement(url);
        assertThat(metadataStatement).isNotNull();
    }
}
