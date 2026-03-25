package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * An {@link OriginPredicate} implementation that validates origins against a predefined set.
 * <p>
 * This predicate returns {@code true} only if the tested origin is contained in the
 * configured set of allowed origins. This is the recommended implementation for production
 * use, as it enforces strict origin validation as required by WebAuthn Level 3 § 13.4.9.
 * <p>
 * The predicate performs exact matching of origins, including scheme, host, and port.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-validating-origin">WebAuthn Level 3 § 13.4.9 Validating the origin of a credential</a>
 */
public class SimpleOriginPredicate implements OriginPredicate {

    private final Set<Origin> origins;

    /**
     * Constructs a predicate that accepts origins from the specified set.
     *
     * @param origins the set of allowed origins
     */
    SimpleOriginPredicate(Set<Origin> origins) {
        this.origins = origins;
    }

    /**
     * Constructs a predicate that accepts only a single origin.
     *
     * @param origin the allowed origin
     */
    SimpleOriginPredicate(Origin origin) {
        this.origins = Collections.singleton(origin);
    }

    /**
     * Tests whether the given origin is in the allowed set.
     *
     * @param origin the origin to test
     * @return {@code true} if the origin is in the allowed set, {@code false} otherwise
     */
    @Override
    public boolean test(Origin origin) {
        return origins.contains(origin);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SimpleOriginPredicate that = (SimpleOriginPredicate) o;
        return Objects.equals(origins, that.origins);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(origins);
    }

    @Override
    public String toString() {
        return "SimpleOriginPredicate{" +
                "origins=" + origins +
                '}';
    }
}
