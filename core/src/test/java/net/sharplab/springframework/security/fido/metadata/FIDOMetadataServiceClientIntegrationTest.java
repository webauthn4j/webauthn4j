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

package net.sharplab.springframework.security.fido.metadata;

import net.sharplab.springframework.security.fido.metadata.structure.MetadataStatement;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayload;
import net.sharplab.springframework.security.fido.metadata.structure.MetadataTOCPayloadEntry;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.io.Console;
import java.net.URI;

/**
 * Test for FIDOMetadataServiceClient
 */

public class FIDOMetadataServiceClientIntegrationTest {

    private FIDOMetadataServiceClient target;

    @Before
    public void setup(){
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        target = new FIDOMetadataServiceClient(restTemplate, resourceLoader);
    }

    @Test
    public void retrieveMetadataTOC_test(){
        MetadataTOCPayload metadataTOC = target.retrieveMetadataTOC();

    }

    @Test
    public void retrieveMetadataStatement_test() throws Exception{
        URI uri = new URI("https://mds.fidoalliance.org/metadata/4e4e%23400a");
        MetadataStatement metadataStatement = target.retrieveMetadataStatement(uri);

    }
}
