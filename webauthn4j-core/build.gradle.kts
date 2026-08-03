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
}

description = "WebAuthn4J Core library"

testing {
    suites {
        register<JvmTestSuite>("testWithBouncyCastle") {
            targets {
                all {
                    testTask.configure {
                        description = "Runs tests with BouncyCastle as the primary JCA provider"
                        testClassesDirs = sourceSets["test"].output.classesDirs
                        classpath = sourceSets["test"].runtimeClasspath
                        systemProperty("java.security.properties",
                            file("src/test/resources/bc-provider.security").absolutePath)
                        systemProperty("webauthn4j.test.securityProvider", "BC")
                    }
                }
            }
        }
    }
}

tasks.named("test") {
    dependsOn(testing.suites.named("testWithBouncyCastle"))
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
