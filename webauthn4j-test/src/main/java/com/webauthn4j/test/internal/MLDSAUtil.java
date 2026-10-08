package com.webauthn4j.test.internal;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;

import java.security.SecureRandom;

/**
 * Generates ML-DSA key material using Bouncy Castle's low-level API.
 * <p>
 * Bouncy Castle references must be confined to this class so that
 * classes using it (TestDataUtil, WebAuthnModelAuthenticator, etc.)
 * do not trigger NoClassDefFoundError in environments where only
 * BC-FIPS is on the classpath. The JVM defers class loading of this
 * class until a method is actually called.
 */
public class MLDSAUtil {

    private MLDSAUtil() {
    }

    public static MLDSAKeyMaterial generateKeyMaterial(String jcaName) {
        MLDSAParameters params = getMLDSAParameters(jcaName);
        MLDSAKeyPairGenerator generator = new MLDSAKeyPairGenerator();
        generator.init(new MLDSAKeyGenerationParameters(new SecureRandom(), params));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        MLDSAPrivateKeyParameters privateKey = (MLDSAPrivateKeyParameters) keyPair.getPrivate();
        MLDSAPublicKeyParameters publicKey = (MLDSAPublicKeyParameters) keyPair.getPublic();
        return new MLDSAKeyMaterial(privateKey.getSeed(), publicKey.getEncoded());
    }

    private static MLDSAParameters getMLDSAParameters(String jcaName) {
        switch (jcaName) {
            case "ML-DSA-44": return MLDSAParameters.ml_dsa_44;
            case "ML-DSA-65": return MLDSAParameters.ml_dsa_65;
            case "ML-DSA-87": return MLDSAParameters.ml_dsa_87;
            default: throw new IllegalArgumentException("Unsupported ML-DSA algorithm: " + jcaName);
        }
    }
}
