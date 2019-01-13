package com.webauthn4j.anchor;

import com.webauthn4j.util.CertificateUtil;

import java.io.InputStream;
import java.security.cert.TrustAnchor;
import java.util.*;

/**
 * NOT FOR PRODUCTION USE
 */
public class SampleTrustAnchorProvider extends CachingTrustAnchorProviderBase {

    private List<String> classPaths;

    public SampleTrustAnchorProvider(){
        this.classPaths = Collections.singletonList("attestation/google/google-root-CA.crt");
    }

    @Override
    protected Map<byte[], Set<TrustAnchor>> loadTrustAnchors() {
        Set<TrustAnchor> set = new HashSet<>();
        for(String classPath : classPaths){
            InputStream inputStream = this.getClass().getClassLoader()
                    .getResourceAsStream(classPath);
            TrustAnchor trustAnchor = new TrustAnchor(CertificateUtil.generateX509Certificate(inputStream), null);
            set.add(trustAnchor);
        }
        return Collections.singletonMap(null, set);
    }

}
