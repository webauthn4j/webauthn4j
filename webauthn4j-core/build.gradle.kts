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

plugins {
    id("webauthn4j.java-library-conventions")
    id("com.webauthn4j.test-with-security-provider")
}

description = "WebAuthn4J Core library"

testing {
    suites {
        // Re-runs src/test/java tests with BouncyCastle as the primary JCA provider,
        // simulating environments where BC is registered at highest priority.
        register<JvmTestSuite>("testWithBouncyCastle") {
            dependencies {
                implementation(project())
                implementation(project(":webauthn4j-test"))
                implementation(project(":webauthn4j-core-async"))
                implementation(libs.bouncycastle.bcprov.jdk18on)
                implementation(libs.bouncycastle.bcpkix.jdk18on)
                implementation(platform(libs.spring.boot.bom))
                implementation("ch.qos.logback:logback-classic")
                implementation("org.projectlombok:lombok")
                implementation("org.mockito:mockito-junit-jupiter")
                implementation("org.assertj:assertj-core")
            }
            targets {
                all {
                    testTask.configure {
                        description = "Runs tests with BouncyCastle as the primary JCA provider"
                        testClassesDirs = sourceSets["test"].output.classesDirs
                        classpath += sourceSets["test"].output
                    }
                }
            }
        }
        // Re-runs src/test/java tests with BouncyCastle FIPS as the primary JCA provider.
        // BC and BC-FIPS are mutually exclusive and cannot coexist on the same classpath.
        // Runs only on Linux because the JENT entropy provider requires native code
        // that is only available on Intel/ARM Linux (see BC-FJA User Guide Section 2.4).
        register<JvmTestSuite>("testWithBouncyCastleFIPS") {
            dependencies {
                implementation(project())
                implementation(project(":webauthn4j-test"))
                implementation(project(":webauthn4j-core-async"))
                implementation(libs.bouncycastle.bc.fips)
                implementation(libs.bouncycastle.bcpkix.fips)
                implementation(libs.bouncycastle.bc.rng.jent)
                implementation(platform(libs.spring.boot.bom))
                implementation("ch.qos.logback:logback-classic")
                implementation("org.projectlombok:lombok")
                implementation("org.mockito:mockito-junit-jupiter")
                implementation("org.assertj:assertj-core")
            }
            targets {
                all {
                    testTask.configure {
                        description = "Runs tests with BouncyCastle FIPS as the primary JCA provider (Linux only)"
                        testClassesDirs = sourceSets["test"].output.classesDirs
                        classpath += sourceSets["test"].output
                        onlyIf { System.getProperty("os.name").lowercase().contains("linux") }
                    }
                }
            }
        }
    }
}

// Exclude regular BouncyCastle from the BC-FIPS test suite classpaths.
// The OptionalDependenciesPlugin adds optional dependencies (including bcprov) to all
// source sets' classpaths, so we must explicitly exclude them here.
configurations.named("testWithBouncyCastleFIPSCompileClasspath") {
    exclude(group = "org.bouncycastle", module = "bcprov-jdk18on")
    exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
}
configurations.named("testWithBouncyCastleFIPSRuntimeClasspath") {
    exclude(group = "org.bouncycastle", module = "bcprov-jdk18on")
    exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
}

// Configure which JCA security providers are active for each test suite.
// The test-with-security-provider plugin registers the listed providers via
// java.security.properties and removes all others via a Java agent premain.
testWithSecurityProvider {
    configurations {
        register("testWithBouncyCastle") {
            // BC as primary provider; SUN retained for entropy (BC's DRBG needs it for seeding)
            providers.set(listOf(
                "org.bouncycastle.jce.provider.BouncyCastleProvider",
                "sun.security.provider.Sun"
            ))
        }
        register("testWithBouncyCastleFIPS") {
            // BC-FIPS as primary provider with JENT-based entropy (no SUN dependency).
            // securerandom.strongAlgorithms must point to the JENT provider to avoid
            // infinite recursion when BC-FIPS initializes its DRBG.
            providers.set(listOf(
                "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider",
                "org.bouncycastle.entropy.provider.BouncyCastleEntropyProvider"
            ))
            securityProperties.put("securerandom.strongAlgorithms", "ENTROPY:BCRNG")
        }
    }
}

tasks.named("test") {
    dependsOn(testing.suites.named("testWithBouncyCastle"))
    dependsOn(testing.suites.named("testWithBouncyCastleFIPS"))
}

dependencies {
    api(libs.jackson.databind)
    api(libs.jackson.dataformat.cbor)
    implementation(libs.slf4j.api)

    //CompileOnly
    compileOnly(libs.jetbrains.annotations)

    //Test
    testImplementation(platform(libs.spring.boot.bom))

    testImplementation(project(":webauthn4j-test"))
    testImplementation(project(":webauthn4j-core-async"))
    testImplementation(libs.bouncycastle.bcprov.jdk18on)
    testImplementation(libs.bouncycastle.bcpkix.jdk18on)
    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.projectlombok:lombok")
    testImplementation("org.mockito:mockito-junit-jupiter")
    testImplementation("org.assertj:assertj-core")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testCompileOnly(libs.jetbrains.annotations)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
