package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

/**
 * An {@link OriginPredicate} implementation that accepts any origin.
 * <p>
 * This predicate always returns {@code true} for any origin value, effectively
 * bypassing origin validation. This can be useful for testing or development
 * environments, but should <strong>never be used in production</strong> as it
 * violates the security model of WebAuthn.
 * <p>
 * According to WebAuthn Level 3 § 13.4.9, Relying Parties must validate that
 * origins match their expectations to prevent cross-origin attacks.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-validating-origin">WebAuthn Level 3 § 13.4.9 Validating the origin of a credential</a>
 */
public class AnyOriginPredicate implements OriginPredicate {
    /**
     * Always returns {@code true}, accepting any origin.
     *
     * @param origin the origin to test (ignored)
     * @return always {@code true}
     */
    @Override
    public boolean test(Origin origin) {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        return true;
    }

    @Override
    public int hashCode() {
        return 31;
    }

    @Override
    public String toString() {
        return "(any origin)";
    }
}
