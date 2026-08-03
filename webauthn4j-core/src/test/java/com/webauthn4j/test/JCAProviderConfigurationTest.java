package com.webauthn4j.test;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class JCAProviderConfigurationTest {

    @Test
    void bc_is_not_registered_by_default() {
        Assumptions.assumeTrue(System.getProperty("webauthn4j.test.securityProvider") == null);
        assertThat(Arrays.stream(Security.getProviders()).map(Provider::getName))
                .doesNotContain("BC");
    }

    @Test
    void bc_is_primary_provider_with_sun_for_entropy() {
        Assumptions.assumeTrue("BC".equals(System.getProperty("webauthn4j.test.securityProvider")));
        List<String> providerNames = Arrays.stream(Security.getProviders())
                .map(Provider::getName)
                .collect(Collectors.toList());
        assertThat(providerNames.get(0)).isEqualTo("BC");
        assertThat(providerNames).contains("SUN");
        assertThat(providerNames).doesNotContain("SunEC", "SunRsaSign", "SunJSSE", "SunJCE");
    }
}
