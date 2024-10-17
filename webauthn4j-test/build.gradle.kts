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

description = "Package that contains testing classes for WebAuthn4J"

dependencies {
    implementation(project(":webauthn4j-core"))
    implementation(project(":webauthn4j-appattest"))
    implementation(project(":webauthn4j-metadata"))
    implementation(project(":webauthn4j-core-async"))

    implementation(libs.slf4j.api)
    implementation(libs.jackson.databind)
    implementation(libs.jackson.dataformat.cbor)

    implementation(libs.bouncycastle.bcprov.jdk15to18)
    implementation(libs.bouncycastle.bcpkix.jdk15to18)

    //CompileOnly
    compileOnly(libs.jetbrains.annotations)

    //Test
    testImplementation(platform(libs.spring.boot.bom))

    testImplementation("ch.qos.logback:logback-classic")
    testImplementation("org.projectlombok:lombok")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.assertj:assertj-core")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")

}

sonarqube {
    isSkipProject = true
}
