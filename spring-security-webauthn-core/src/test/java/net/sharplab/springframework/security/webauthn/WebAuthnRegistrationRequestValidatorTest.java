/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn;

import com.webauthn4j.context.validator.WebAuthnRegistrationContextValidator;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import net.sharplab.springframework.security.webauthn.context.provider.RelyingPartyProviderImpl;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;

/**
 * Test for WebAuthnRegistrationContextValidator
 */
public class WebAuthnRegistrationRequestValidatorTest {

    private WebAuthnRegistrationRequestValidator target;

    @Test
    @Ignore
    public void test() {
        target = new WebAuthnRegistrationRequestValidator(new WebAuthnRegistrationContextValidator(Collections.emptyList()), new RelyingPartyProviderImpl(new HttpSessionChallengeRepository()));

        String clientDataBase64 = "eyJjaGFsbGVuZ2UiOiJGRkc1UVdrRFNJUzZvRVY1SFc0Vlp3IiwiaGFzaEFsZyI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ";
        String authenticatorDataBase64 = "o2hhdXRoRGF0YVjaSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAUPkhL7CLReeOjs15K_lZ-dzAl9qiMLFVDiPhCy47YK_CATKTTfSYeJkcPxlk1VVuk7tFqXWom7EIvN9JEq1efGIt2KXm4mtYuHJNpWP6wUlNo2NhbGdlRVMyNTZheFgga1LrLL5aWxB9DSl3MaBK1swOMYFFyT_VKKxjAee7T5JheVgggnPC8LwHjrU7xRjo8apkgI88lJOL6TLMJuvWkkQbWQhjZm10aGZpZG8tdTJmZ2F0dFN0bXSiY3g1Y4FZAVAwggFMMIHzoAMCAQICCswWCqfhOU9rd1AwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAxMMRlQgRklETyAwMTAwMB4XDTE2MDQxNTE0NTAzMloXDTI2MDQxNTE0NTAzMlowJzElMCMGA1UEAxMcRlQgRklETyBVMkYgMTE2MTYxNzMwMzA1MDIxMDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMbW1eH0fIaLhQlqmw_cXDw0TBGvlYRh9XnE68_ZdTiOmcnXtIRvJlMKfutffwSm3fYE-voho6ZqaoB1C-wOk2CjFzAVMBMGCysGAQQBguUcAgEBBAQDAgQwMAoGCCqGSM49BAMCA0gAMEUCIQDfA-8s6-OltTdUKwoGNa1vkzNxf8jans039fTeTLIWhQIgDGgk-KcoZTGg1H9uHHe5ke1BCnAta5oE0P3LY6aF_jtjc2lnWEcwRQIhAMhC6-Zl4aBd9qUxN-YL4iuk5fJiJT0u5O-ryg6ZRqgcAiAt9emh9-KE98O_4D5HgNUfTwMmyYPSkSCcSpuiBNU0jw";

        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setScheme("http");
        mockHttpServletRequest.setServerName("localhost");
        mockHttpServletRequest.setServerPort(8080);
        target.validate(mockHttpServletRequest, null, clientDataBase64, authenticatorDataBase64);
    }

}
