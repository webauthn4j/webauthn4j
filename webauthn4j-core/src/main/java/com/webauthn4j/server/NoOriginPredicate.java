package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

/**
 * An {@link OriginPredicate} implementation that rejects all origins.
 * <p>
 * This predicate always returns {@code false} for any origin value, effectively
 * rejecting all cross-origin WebAuthn operations.
 * <p>
 * This is primarily used as a {@code topOriginPredicate} to disallow cross-origin
 * iframe scenarios. When used (or when topOriginPredicate is null), it ensures that
 * WebAuthn operations are only permitted in same-origin contexts, blocking any
 * cross-origin usage.
 * <p>
 * According to WebAuthn Level 3 § 7.1 Step 13-14 and § 7.2 Step 13-14, when C.crossOrigin
 * is true or C.topOrigin is present, the Relying Party must verify that it expects the
 * credential to be used within an iframe that is not same-origin with its ancestors.
 * Using {@code NoOriginPredicate} (or leaving topOriginPredicate as null) enforces that
 * such cross-origin scenarios are not allowed.
 * <p>
 * Note: In the current implementation, {@code NoOriginPredicate} has the same effect as
 * setting topOriginPredicate to null - both will reject all cross-origin requests.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-validating-origin">WebAuthn Level 3 § 13.4.9 Validating the origin of a credential</a>
 */
public class NoOriginPredicate implements OriginPredicate {
    /**
     * Always returns {@code false}, rejecting any origin.
     *
     * @param origin the origin to test (ignored)
     * @return always {@code false}
     */
    @Override
    public boolean test(Origin origin) {
        return false;
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
        return "NoOriginPredicate{}";
    }
}
