package com.webauthn4j.data.attestation.authenticator.internal;

import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;

/**
 * Expands an ML-DSA 32-byte seed into an expanded private key using Bouncy Castle.
 * <p>
 * Bouncy Castle references must be confined to this class and not appear in
 * {@link com.webauthn4j.data.attestation.authenticator.AKPCOSEKey AKPCOSEKey} directly.
 * If {@code AKPCOSEKey} had methods whose signatures or bodies referenced BC types,
 * the JVM would attempt to load those types when Jackson introspects the class
 * (e.g., via {@code Class.getDeclaredMethods}), causing {@code NoClassDefFoundError}
 * even when only public-key operations are used. By isolating BC usage here, the JVM
 * defers class loading until {@code AKPCOSEKey.getPrivateKey()} actually calls {@link #expand}.
 */
public class MLDSASeedExpander {

    private MLDSASeedExpander() {
    }

    public static byte[] expand(byte[] seed, String jcaName) {
        MLDSAParameters params = getMLDSAParameters(jcaName);
        MLDSAPrivateKeyParameters bcPriv = new MLDSAPrivateKeyParameters(params, seed);
        // Returns the raw expanded key (expandedKey CHOICE in PKCS#8).
        // Do NOT replace with BCMLDSAPrivateKey.getEncoded(), which emits
        // the "both" CHOICE (seed + expanded) that the JDK SUN provider rejects.
        return bcPriv.getEncoded();
    }

    private static MLDSAParameters getMLDSAParameters(String jcaName) {
        switch (jcaName) {
            case "ML-DSA-44":
                return MLDSAParameters.ml_dsa_44;
            case "ML-DSA-65":
                return MLDSAParameters.ml_dsa_65;
            case "ML-DSA-87":
                return MLDSAParameters.ml_dsa_87;
            default:
                throw new IllegalArgumentException("Unsupported ML-DSA algorithm: " + jcaName);
        }
    }
}
