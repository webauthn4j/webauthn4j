package com.webauthn4j.client;

import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenBindingTest {

    @Test
    public void constructor_test(){
        TokenBinding tokenBindingA = new TokenBinding(TokenBindingStatus.SUPPORTED, Base64UrlUtil.encodeToString(new byte[]{0x01, 0x23, 0x45}));
        TokenBinding tokenBindingB = new TokenBinding(TokenBindingStatus.SUPPORTED, new byte[]{0x01, 0x23, 0x45});

        assertThat(tokenBindingA).isEqualTo(tokenBindingB);
    }

    @Test
    public void equals_hashCode_test(){
        TokenBinding tokenBindingA = new TokenBinding(TokenBindingStatus.SUPPORTED, new byte[]{0x01, 0x23, 0x45});
        TokenBinding tokenBindingB = new TokenBinding(TokenBindingStatus.SUPPORTED, new byte[]{0x01, 0x23, 0x45});

        assertThat(tokenBindingA).isEqualTo(tokenBindingB);
        assertThat(tokenBindingA).hasSameHashCodeAs(tokenBindingB);
    }



}
