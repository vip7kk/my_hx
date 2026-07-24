/*
 * ProGuard -- shrinking, optimization, obfuscation, and preverification
 *             of Java bytecode.
 *
 * Copyright (c) 2002-2020 Guardsquare NV
 */

package proguard.gradle

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.gradle.testkit.runner.TaskOutcome
import testutils.AndroidProject
import testutils.SourceFile
import testutils.applicationModule
import testutils.createGradleRunner
import testutils.createTestKitDir
import testutils.libraryModule

class ProGuardPluginTest : FreeSpec({
    val testKitDir = createTestKitDir()

    "Given a project without the Android Gradle plugin" - {
        val project = autoClose(AndroidProject().apply {
            addModule(applicationModule("app", buildDotGradle = """
                    plugins {
                        id 're.obfuscator.dprotect'
                    }
                    """.trimIndent()))
        }.create())

        "When the project is evaluated" - {
            val result = createGradleRunner(project.rootDir, testKitDir).buildAndFail()

            "Then the build should fail" {
                result.output shouldContain "Failed to apply plugin 're.obfuscator.dprotect'"
            }
        }
    }

    "Given a project with an old Android Gradle plugin" - {
        val project = autoClose(AndroidProject("""
            buildscript {
                repositories {
                    mavenCentral() // For anything else.
                    google()       // For the Android plugin.
                    flatDir {
                        dirs "${System.getProperty("local.repo")}"
                    }
                }
                dependencies {
                    classpath "com.android.tools.build:gradle:3.6.3"
                    classpath ":proguard-gradle:${System.getProperty("proguard.version")}"
                }
            }
            allprojects {
                repositories {
                    google()
                    mavenCentral()
                }
            }
            """.trimIndent()).apply {
                addModule(applicationModule("app", buildDotGradle = """
                            plugins {
                                id 'com.android.application'
                                id 're.obfuscator.dprotect'
                            }

                            android {
                                compileSdk 33

                                buildTypes {
                                    release {}
                                    debug   {}
                                }
                            }

                            dProtect {
                                configurations {
                                    release {}
                                }
                            }
                            """.trimIndent()))
            }.create())

        "When the project is evaluated" - {
            val result = createGradleRunner(project.rootDir, testKitDir).buildAndFail()

            "Then the build should fail" {
                result.output shouldContain "requires AGP 7.0 or higher"
            }
        }
    }

    "Given a library project" - {
        val project = autoClose(AndroidProject().apply {
            addModule(libraryModule("lib", buildDotGradle = """
            plugins {
                id 'com.android.library'
                id 're.obfuscator.dprotect'
            }

            android {
                namespace 'com.example.lib'
                compileSdk 33

                buildTypes {
                    release {
                        minifyEnabled false
                    }
                    debug   {}
                }
            }

            dProtect {
                configurations {
                    release {
                        defaultConfiguration 'proguard-android.txt'
                        configuration 'proguard-project.txt'
                    }
                }
            }
            """.trimIndent(),
            additionalFiles = listOf(SourceFile("proguard-project.txt", "-keep class **"))))
        }.create())

        "When the project is assembled" - {
            val result = createGradleRunner(project.rootDir, testKitDir, "assembleRelease").build()

            "Then the build should succeed" {
                result.task(":lib:assembleRelease")?.outcome shouldBe TaskOutcome.SUCCESS
            }
        }
    }
})
