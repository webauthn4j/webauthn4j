package com.webauthn4j.test.integration.spc;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.openqa.selenium.By;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.HttpCommandExecutor;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.virtualauthenticator.HasVirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@QuarkusTest
@EnabledOnOs({OS.WINDOWS, OS.MAC})
public class SPCEndToEndTest {

    private static final int PORT = 8080;
    private static final String BANK_BASE_URL = "http://bank.localhost:" + PORT;
    private static final String MERCHANT_BASE_URL = "http://merchant.localhost:" + PORT;

    private ChromeDriver driver;
    private VirtualAuthenticator authenticator;

    @BeforeEach
    void setup() throws IOException, InterruptedException {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless=new", "--no-sandbox", "--disable-dev-shm-usage");
        driver = new ChromeDriver(options);

        VirtualAuthenticatorOptions authOptions = new VirtualAuthenticatorOptions()
                .setProtocol(VirtualAuthenticatorOptions.Protocol.CTAP2)
                .setTransport(VirtualAuthenticatorOptions.Transport.INTERNAL)
                .setHasResidentKey(true)
                .setHasUserVerification(true)
                .setIsUserVerified(true);
        authenticator = ((HasVirtualAuthenticator) driver).addVirtualAuthenticator(authOptions);

        // SPC spec §10.1: Set SPC Transaction Mode via WebDriver extension command
        setSPCTransactionMode("autoAccept");
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            try { setSPCTransactionMode("none"); } catch (Exception ignored) {}
            try { ((HasVirtualAuthenticator) driver).removeVirtualAuthenticator(authenticator); } catch (Exception ignored) {}
            try { driver.quit(); } catch (Exception ignored) {}
        }
    }

    /**
     * Send the SPC WebDriver extension command directly to ChromeDriver's HTTP endpoint.
     * SPC spec §10.1: POST /session/{session id}/secure-payment-confirmation/set-mode
     */
    private void setSPCTransactionMode(String mode) throws IOException, InterruptedException {
        HttpCommandExecutor executor = (HttpCommandExecutor) driver.getCommandExecutor();
        String baseUrl = executor.getAddressOfRemoteServer().toString();
        if (!baseUrl.endsWith("/")) {
            baseUrl += "/";
        }
        String sessionId = driver.getSessionId().toString();
        String url = baseUrl + "session/" + sessionId + "/secure-payment-confirmation/set-mode";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"mode\":\"" + mode + "\"}"))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to set SPC Transaction Mode: " + response.body());
        }
    }

    @Test
    void testSPCCrossOriginRegistrationAndAuthentication() {
        // 1. Register on the RP's domain (bank.localhost)
        driver.get(BANK_BASE_URL + "/register.html");
        assertThat(driver.getTitle()).isEqualTo("SPC Registration - Bank");

        driver.findElement(By.id("register-btn")).click();

        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        wait.until(d -> {
            String status = d.findElement(By.id("status")).getText();
            return !"Registering...".equals(status) && !"Ready".equals(status);
        });

        String regStatus = driver.findElement(By.id("status")).getText();
        String regResult = driver.findElement(By.id("result")).getText();
        assertThat(regStatus).describedAs("Registration result: %s", regResult)
                .isEqualTo("Registration successful");

        // 2. Authenticate on the merchant's domain (merchant.localhost)
        //    This demonstrates SPC's cross-origin capability:
        //    the credential was registered on bank.localhost,
        //    but authentication is initiated from merchant.localhost.
        driver.get(MERCHANT_BASE_URL + "/pay.html");
        assertThat(driver.getTitle()).isEqualTo("SPC Payment - Merchant");

        driver.findElement(By.id("pay-btn")).click();

        wait.until(d -> {
            String status = d.findElement(By.id("status")).getText();
            return !"Authenticating...".equals(status) && !"Ready".equals(status);
        });

        String authStatus = driver.findElement(By.id("status")).getText();
        String authResult = driver.findElement(By.id("result")).getText();
        assertThat(authStatus).describedAs("Authentication result: %s", authResult)
                .isEqualTo("Authentication successful");
    }
}
