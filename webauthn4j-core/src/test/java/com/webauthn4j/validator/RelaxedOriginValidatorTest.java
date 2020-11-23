package com.webauthn4j.validator;

import com.webauthn4j.data.client.Origin;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RelaxedOriginValidatorTest {
    
    @Test
    void validateSameHttpsOrigin_test() {
        Origin origin1 = new Origin("https://my.fido2/");
        Origin origin2 = new Origin("https://my.fido2/");
        assertTrue(origin1.matchesRelaxed(origin2));
    }

    @Test
    void validateDifferentHttpsOrigin_test() {
        Origin origin1 = new Origin("https://my.fido2/");
        Origin origin2 = new Origin("https://other.fido/");
        assertFalse(origin1.matchesRelaxed(origin2));
    }

    @Test
    void validateDifferentScheme_test() {
        Origin origin1 = new Origin("https://my.fido2/");
        Origin origin2 = new Origin("http://my.fido2/");
        Origin origin3 = new Origin("android://my.fido2/");
        assertFalse(origin1.matchesRelaxed(origin2));
        assertFalse(origin1.matchesRelaxed(origin3));
    }

    @Test
    void validateDifferentPort_test() {
        Origin origin1 = new Origin("https://my.fido2/");
        Origin origin2 = new Origin("https://my.fido2:8443/");
        assertTrue(origin1.matchesRelaxed(origin2));

        origin1 = new Origin("http://my.fido2:20/");
        origin2 = new Origin("http://my.fido2:30/");
        assertTrue(origin1.matchesRelaxed(origin2));
    }

    @Test
    void validateSubdomain_test() {
        Origin origin1 = new Origin("https://my.fido2.com/");
        Origin origin2 = new Origin("https://myother.fido2.com/");
        Origin origin3 = new Origin("https://fido2.com/");
        assertTrue(origin1.matchesRelaxed(origin3));
        assertTrue(origin2.matchesRelaxed(origin3));
    }
    
}