/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.test.integration.spring.security;

import com.google.gson.JsonObject;
import com.microsoft.playwright.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class WebAuthn4jSpringSecurityE2ETest {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthn4jSpringSecurityE2ETest.class);

    @LocalServerPort
    private int port;

    private Playwright playwright;
    private Browser browser;
    private BrowserContext context;
    private Page page;

    @BeforeEach
    void setup() {
        playwright = Playwright.create();
        BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions()
                .setHeadless(true)
                .setArgs(List.of("--no-sandbox", "--disable-dev-shm-usage"));
        browser = playwright.chromium().launch(launchOptions);

        context = browser.newContext(new Browser.NewContextOptions());
        page = context.newPage();

        page.onConsoleMessage(msg -> {
            String type = String.valueOf(msg.type());
            String text = msg.text();
            if ("error".equalsIgnoreCase(type)) {
                logger.error("BROWSER: {}", text);
            } else if ("warning".equalsIgnoreCase(type) || "warn".equalsIgnoreCase(type)) {
                logger.warn("BROWSER: {}", text);
            } else {
                logger.info("BROWSER [{}]: {}", type, text);
            }
        });
        page.onPageError(error -> logger.error("PAGE ERROR: {}", error));
        context.onRequestFailed(request -> logger.error("REQUEST FAILED: {} {}", request.method(), request.url()));
        context.onResponse(response -> {
            int status = response.status();
            if (status >= 500) {
                logger.error("HTTP {} {}", status, response.url());
            } else if (status >= 400) {
                logger.warn("HTTP {} {}", status, response.url());
            }
        });

        CDPSession cdp = context.newCDPSession(page);
        JsonObject enableParams = new JsonObject();
        cdp.send("WebAuthn.enable", enableParams);

        JsonObject options = new JsonObject();
        options.addProperty("protocol", "ctap2");
        options.addProperty("transport", "internal");
        options.addProperty("hasResidentKey", true);
        options.addProperty("hasUserVerification", true);
        options.addProperty("isUserVerified", true);
        options.addProperty("automaticPresenceSimulation", true);

        JsonObject params = new JsonObject();
        params.add("options", options);
        cdp.send("WebAuthn.addVirtualAuthenticator", params);
    }

    @AfterEach
    void tearDown() {
        try {
            if (context != null) {
                context.close();
            }
        } catch (Exception ignored) {
        }
        try {
            if (browser != null) {
                browser.close();
            }
        } catch (Exception ignored) {
        }
        try {
            if (playwright != null) {
                playwright.close();
            }
        } catch (Exception ignored) {
        }
    }

    @Test
    void testSignupAndPasswordLoginWith2FA() {
        String baseUrl = "http://localhost:" + port;

        // Sign up without single-factor authentication
        page.navigate(baseUrl + "/signup");
        page.fill("#username", "testuser");
        page.fill("#password", "password123");
        page.click("#authenticator");
        page.waitForSelector("#submit:not([disabled])");
        page.click("#submit");
        page.waitForURL(baseUrl + "/login");

        // Login with password (triggers 2FA via authenticator-login page)
        page.fill("#username", "testuser");
        page.fill("#password", "password123");
        page.click("#login");

        // After password login, user is redirected to / but access is denied
        // (requires WebAuthn auth), so redirected to /login which shows
        // authenticator-login page. The page auto-triggers getCredential
        // and auto-submits the form. Wait for dashboard.
        page.waitForSelector("#dashboard-view", new Page.WaitForSelectorOptions().setTimeout(60000));

        assertThat(page.title()).isEqualTo("WebAuthn4J Spring Security Integration Test");
        assertThat(page.locator("h3").textContent()).contains("Login success");

        // Logout
        page.click("form button[type='submit']");
        page.waitForURL(java.util.regex.Pattern.compile("/login"), new Page.WaitForURLOptions().setTimeout(10000));
    }

    @Test
    void testSignupWithSingleFactorAndPasskeyLogin() {
        String baseUrl = "http://localhost:" + port;

        // Sign up with single-factor authentication allowed
        page.navigate(baseUrl + "/signup");
        page.fill("#username", "passkeyuser");
        page.fill("#password", "password123");
        page.click("#authenticator");
        page.waitForSelector("#submit:not([disabled])");
        page.check("#singleFactorAuthenticationAllowed");
        page.click("#submit");
        page.waitForURL(baseUrl + "/login");

        // Login with passkey
        page.click("#fast-login");
        page.waitForURL(baseUrl + "/");

        assertThat(page.title()).isEqualTo("WebAuthn4J Spring Security Integration Test");
        assertThat(page.locator("h3").textContent()).contains("Login success");
    }
}
