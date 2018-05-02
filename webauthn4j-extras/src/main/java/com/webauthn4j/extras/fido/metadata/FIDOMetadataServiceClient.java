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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.webauthn4j.extras.fido.metadata.structure.MetadataStatement;
import com.webauthn4j.extras.fido.metadata.structure.MetadataTOCPayload;
import com.webauthn4j.jackson.ObjectMapperUtil;
import com.webauthn4j.util.WIP;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;

/**
 * Client for FIDO Metadata Service
 */
@WIP
public class FIDOMetadataServiceClient {

    RestTemplate restTemplate;

    JWSVerifier jwsVerifier;

    ObjectMapper objectMapper;

    private static final String DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT = "https://mds.fidoalliance.org/";

    private String fidoMetadataServiceEndpoint;

    public FIDOMetadataServiceClient(RestTemplate restTemplate, JWSVerifier jwsVerifier, String fidoMetadataServiceEndpoint) {
        this.restTemplate = restTemplate;
        this.jwsVerifier = jwsVerifier;
        this.fidoMetadataServiceEndpoint = fidoMetadataServiceEndpoint;

        objectMapper = ObjectMapperUtil.createJSONMapper();
    }

    public FIDOMetadataServiceClient(RestTemplate restTemplate, JWSVerifier jwsVerifier) {
        this(restTemplate, jwsVerifier, DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT);
    }

    public FIDOMetadataServiceClient(RestTemplate restTemplate, ResourceLoader resourceLoader) {
        this(restTemplate, new CertPathJWSVerifier(resourceLoader));
    }

    public MetadataTOCPayload retrieveMetadataTOC() {
        ResponseEntity<String> responseEntity = restTemplate.getForEntity(fidoMetadataServiceEndpoint, String.class);
        SignedJWT jwt;
        try {
            jwt = (SignedJWT) JWTParser.parse(responseEntity.getBody());
        } catch (ParseException e) {
            throw new IllegalStateException(e);
        }

        //Verify JWS Signature
        jwsVerifier.verify(jwt);

        String payloadString = jwt.getPayload().toString();
        MetadataTOCPayload payload;
        try {
            payload = objectMapper.readValue(payloadString, MetadataTOCPayload.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return payload;
    }

    public MetadataStatement retrieveMetadataStatement(URI uri) {
        ResponseEntity<String> responseEntity;
        responseEntity = restTemplate.getForEntity(uri, String.class);
        String decoded = new String(Base64Utils.decodeFromString(responseEntity.getBody()), StandardCharsets.UTF_8);
        try {
            return objectMapper.readValue(decoded, MetadataStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String getFidoMetadataServiceEndpoint() {
        return fidoMetadataServiceEndpoint;
    }

    public void setFidoMetadataServiceEndpoint(String fidoMetadataServiceEndpoint) {
        this.fidoMetadataServiceEndpoint = fidoMetadataServiceEndpoint;
    }


}
