package com.webauthn4j.test;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class JCAProviderConfigurationTest {

    @Test
    void bc_is_not_registered_by_default() {
        Assumptions.assumeTrue(System.getProperty("webauthn4j.test.securityProviders") == null);
        assertThat(Arrays.stream(Security.getProviders()).map(Provider::getName))
                .doesNotContain("BC");
    }

    @Test
    void only_configured_providers_are_registered() {
        String configured = System.getProperty("webauthn4j.test.securityProviders");
        Assumptions.assumeTrue(configured != null);
        Set<String> expectedClasses = Set.of(configured.split(","));
        Set<String> actualClasses = Arrays.stream(Security.getProviders())
                .map(p -> p.getClass().getName())
                .collect(Collectors.toSet());
        assertThat(actualClasses).isEqualTo(expectedClasses);
    }
}
