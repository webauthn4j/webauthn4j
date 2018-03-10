package net.sharplab.springframework.security.webauthn.client;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for Origin
 */
public class OriginTest {

    @Test
    public void equals_test(){
        Origin https_examplecom_default = new Origin("https://example.com");
        Origin https_examplecom_443 = new Origin("https://example.com:443");
        Origin http_examplecom_default = new Origin("http://example.com");
        Origin http_examplecom_80 = new Origin("http://example.com:80");
        Origin http_examplecom_8080 = new Origin("http://example.com:8080");

        assertThat(https_examplecom_default).isEqualTo(https_examplecom_443);
        assertThat(http_examplecom_default).isEqualTo(http_examplecom_80);
        assertThat(http_examplecom_default).isNotEqualTo(http_examplecom_8080);
        assertThat(http_examplecom_default).isNotEqualTo(https_examplecom_default);
    }

    @Test
    public void getter_test(){
        Origin https_examplecom_default = new Origin("https://example.com");
        assertThat(https_examplecom_default.getScheme()).isEqualTo("https");
        assertThat(https_examplecom_default.getServerName()).isEqualTo("example.com");
        assertThat(https_examplecom_default.getPort()).isEqualTo(443);

    }

    @Test
    public void constructor_test(){
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);

        assertThat(originA).isEqualTo(originB);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructor_test_with_illegal_input(){
        new Origin("ftp://example.com");
    }

    @Test
    public void hasCode_test(){
        Origin originA = new Origin("https://example.com");
        Origin originB = new Origin("https", "example.com", 443);

        assertThat(originA.hashCode()).isEqualTo(originB.hashCode());
    }

}
