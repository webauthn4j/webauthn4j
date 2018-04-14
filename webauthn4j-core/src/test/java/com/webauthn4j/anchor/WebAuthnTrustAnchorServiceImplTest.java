package com.webauthn4j.anchor;

import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class WebAuthnTrustAnchorServiceImplTest {

    @Rule
    public MockitoRule mockito = MockitoJUnit.rule();

    @Mock
    private TrustAnchorProvider trustAnchorProvider;

    @InjectMocks
    private WebAuthnTrustAnchorServiceImpl target;

    @Test
    public void getTrustAnchors_test(){
        Set<TrustAnchor> trustAnchorsA = target.getTrustAnchors();
        Set<TrustAnchor> trustAnchorsB = target.getTrustAnchors();

        assertThat(trustAnchorsA).isEqualTo(trustAnchorsB);

        verify(trustAnchorProvider, times(1)).provide();
    }
}
