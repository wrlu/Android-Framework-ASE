import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    `java-library`
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

val jadxVersion = "1.5.5"

dependencies {
    implementation("io.github.skylot:jadx-core:$jadxVersion")
    implementation("io.github.skylot:jadx-dex-input:$jadxVersion")
    implementation("io.github.skylot:jadx-java-input:$jadxVersion")
    implementation("io.github.skylot:jadx-java-convert:$jadxVersion")
    implementation("io.github.skylot:jadx-smali-input:$jadxVersion")
    implementation("com.google.code.gson:gson:2.13.2")
    implementation("org.slf4j:slf4j-simple:2.0.16")
    implementation("org.ow2.asm:asm:9.9")
}

repositories {
    mavenCentral()
    maven(url = "https://s01.oss.sonatype.org/content/repositories/snapshots/")
    google()
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

group = "net.wrlu.android.ase"
version = "1.0.0"

tasks {
    withType(ShadowJar::class) {
        mergeServiceFiles()
        manifest {
            attributes["Main-Class"] = "net.wrlu.android.ase.AnalyzerMain"
        }
        archiveBaseName.set("analyzer")
        archiveClassifier.set("all")
    }

    withType(Test::class) {
        useJUnitPlatform()
    }

    build {
        dependsOn(shadowJar)
    }
}
