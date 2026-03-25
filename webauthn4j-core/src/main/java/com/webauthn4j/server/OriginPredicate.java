package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;

import java.util.function.Predicate;

/**
 * Predicate for validating {@link Origin} values in WebAuthn ceremonies.
 * <p>
 * This interface is used to verify both:
 * <ul>
 *   <li>The origin of a credential (C.origin) as defined in WebAuthn Level 3 § 7.1 Step 12 and § 7.2 Step 12</li>
 *   <li>The top-level origin (C.topOrigin) for cross-origin scenarios as defined in § 7.1 Step 14 and § 7.2 Step 14</li>
 * </ul>
 * Implementations of this interface define different validation strategies:
 * <ul>
 *   <li>{@link SimpleOriginPredicate} - validates against a specific set of allowed origins</li>
 *   <li>{@link AnyOriginPredicate} - accepts any origin (useful for testing, not recommended for production)</li>
 *   <li>{@link NoOriginPredicate} - rejects all origins (for topOrigin validation)</li>
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-validating-origin">WebAuthn Level 3 § 13.4.9 Validating the origin of a credential</a>
 */
public interface OriginPredicate extends Predicate<Origin> {
}
