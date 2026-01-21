package com.webauthn4j.test.integration.spring;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.virtualauthenticator.HasVirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticator;
import org.openqa.selenium.virtualauthenticator.VirtualAuthenticatorOptions;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class PasskeyE2ETest {

    @LocalServerPort
    private int port;

    private WebDriver driver;

    @BeforeEach
    void setup() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        
        driver = new ChromeDriver(options);
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(5));

        VirtualAuthenticatorOptions authOptions = new VirtualAuthenticatorOptions()
                .setTransport(VirtualAuthenticatorOptions.Transport.INTERNAL)
                .setProtocol(VirtualAuthenticatorOptions.Protocol.CTAP2)
                .setHasResidentKey(true)
                .setHasUserVerification(true)
                .setIsUserVerified(true);
        
        ((HasVirtualAuthenticator) driver).addVirtualAuthenticator(authOptions);
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            driver.quit();
        }
    }

    @Test
    void testPasskeyRegistrationAndLogin() {
        String baseUrl = "http://localhost:" + port;
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));

        // 1. Login with password first to register a passkey
        driver.get(baseUrl + "/login");
        driver.findElement(By.name("username")).sendKeys("user");
        driver.findElement(By.name("password")).sendKeys("password");
        driver.findElement(By.cssSelector("button[type='submit']")).click();

        try {
            // Wait for login to complete (title change or h1 element)
            wait.until(ExpectedConditions.titleIs("Spring Security Passkeys Test"));
        } catch (Exception e) {
            System.out.println("Login Failed. Page Source: " + driver.getPageSource());
            throw e;
        }

        assertThat(driver.getTitle()).isEqualTo("Spring Security Passkeys Test");
        assertThat(driver.findElement(By.tagName("h1")).getText()).contains("user");

        // 2. Register a passkey
        driver.get(baseUrl + "/webauthn/register");
        driver.findElement(By.id("label")).sendKeys("My Passkey");
        driver.findElement(By.cssSelector("button")).click();
        
        // Wait for registration completion
        wait.until(d -> d.getCurrentUrl().equals(baseUrl + "/") || d.getCurrentUrl().contains("success"));

        // 3. Logout
        if (!driver.getCurrentUrl().equals(baseUrl + "/")) {
             driver.get(baseUrl + "/");
        }
        driver.findElement(By.cssSelector("form[action='/logout'] button")).click();

        // 4. Login with Passkey
        driver.get(baseUrl + "/login");
        driver.findElement(By.id("passkey-signin")).click();
        
        // 5. Verify successful login
        wait.until(ExpectedConditions.urlToBe(baseUrl + "/"));
        
        assertThat(driver.getTitle()).isEqualTo("Spring Security Passkeys Test");
        assertThat(driver.findElement(By.tagName("h1")).getText()).contains("user");
    }
}
