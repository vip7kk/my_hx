/*
 * ProGuard -- shrinking, optimization, obfuscation, and preverification
 *             of Java bytecode.
 *
 * Copyright (c) 2002-2024 Guardsquare NV
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package proguard.gradle.plugin.android.tasks

import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import proguard.gradle.ProGuardTask

/**
 * Gradle task that runs ProGuard/dProtect on Android project classes.
 *
 * This task replaces the deprecated AGP Transform API ([ProGuardTransform])
 * which was removed in AGP 8.0. It uses the [ScopedArtifacts] API to
 * intercept all compiled classes (jars + directories), run ProGuard
 * obfuscation on them, and produce a single output jar that replaces
 * the original classes in the build pipeline (before dexing).
 *
 * The task is wired via [com.android.build.api.artifact.ScopedArtifacts.forScope]
 * and [com.android.build.api.artifact.ScopedArtifactsOperation.toTransform]
 * in [proguard.gradle.plugin.android.AndroidPlugin].
 */
@CacheableTask
abstract class ProGuardAndroidTask : DefaultTask() {

    // ── ScopedArtifacts inputs (injected by AGP via toTransform) ──

    /** All input jars from the configured scope (project, sub-projects, external libraries). */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val allJars: ListProperty<RegularFile>

    /** All input directories containing compiled classes. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val allDirs: ListProperty<Directory>

    // ── Output (single jar consumed by dexing) ──

    /** Output jar containing the obfuscated/shrunk classes. */
    @get:OutputFile
    abstract val output: RegularFileProperty

    // ── ProGuard configuration ──

    /** User-specified ProGuard configuration files (.pro files). */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val configurationFiles: ConfigurableFileCollection

    /** Consumer ProGuard rules collected from project dependencies. */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val consumerRules: ConfigurableFileCollection

    /** AAPT-generated keep rules (may be empty if not yet generated). */
    @get:InputFiles
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val aaptRules: ConfigurableFileCollection

    /** Library jars on the classpath (not obfuscated; used for reference resolution). */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val libraryJars: ConfigurableFileCollection

    // ── Mapping / debug output ──

    @get:OutputFile
    abstract val mappingFile: RegularFileProperty

    @get:OutputFile
    abstract val seedsFile: RegularFileProperty

    @get:OutputFile
    abstract val usageFile: RegularFileProperty

    // ── Task metadata ──

    @get:Input
    abstract val variantName: Property<String>

    @TaskAction
    fun execute() {
        val variant = variantName.get()
        logger.lifecycle("dProtect: Running ProGuard/dProtect obfuscation for variant '$variant'")

        // Dynamically create and configure a ProGuardTask, then execute it.
        // Use findByName to avoid creating duplicate tasks on re-runs
        // (tasks.remove() is not supported in Gradle 8.x).
        val taskName = "dprotect_proguard_${variant}"
        val existingTask = project.tasks.findByName(taskName)
        val proguardTask = if (existingTask != null && existingTask is ProGuardTask) {
            existingTask
        } else {
            project.tasks.create(taskName, ProGuardTask::class.java)
        }

        // ── Input jars (all classes to be obfuscated) ──
        val inputJars = allJars.get()
        if (inputJars.isEmpty()) {
            logger.warn("dProtect: No input jars found for variant '$variant', skipping obfuscation")
            // Create empty output so downstream tasks don't fail
            output.get().asFile.parentFile.mkdirs()
            output.get().asFile.writeBytes(ByteArray(0))
            return
        }

        inputJars.forEach { jar ->
            logger.debug("dProtect: injars = ${jar.asFile}")
            proguardTask.injars(jar.asFile)
        }

        // ── Input directories (compiled classes) ──
        allDirs.get().forEach { dir ->
            val dirFile = dir.asFile
            if (dirFile.exists() && dirFile.isDirectory && dirFile.listFiles()?.isNotEmpty() == true) {
                logger.debug("dProtect: injars(dir) = $dirFile")
                proguardTask.injars(dirFile)
            }
        }

        // ── Output: single jar with obfuscated classes ──
        val outputFile = output.get().asFile
        outputFile.parentFile.mkdirs()
        logger.debug("dProtect: outjars = $outputFile")
        proguardTask.outjars(outputFile)

        // ── Extra jar (ProGuard internal: stores extra processed classes) ──
        val extraJarFile = outputFile.resolveSibling("extra.jar")
        proguardTask.extraJar(extraJarFile)

        // ── Library jars (classpath, not obfuscated) ──
        libraryJars.files.forEach { libJar ->
            if (libJar.exists()) {
                logger.debug("dProtect: libraryjars = $libJar")
                proguardTask.libraryjars(libJar)
            }
        }

        // ── Configuration files (user rules) ──
        configurationFiles.files.forEach { configFile ->
            if (configFile.exists()) {
                logger.debug("dProtect: configuration = $configFile")
                proguardTask.configuration(configFile)
            }
        }

        // ── Consumer rules (from dependencies) ──
        consumerRules.files.forEach { consumerFile ->
            if (consumerFile.exists()) {
                logger.debug("dProtect: consumer rules = $consumerFile")
                proguardTask.configuration(consumerFile)
            }
        }

        // ── AAPT-generated keep rules ──
        aaptRules.files.forEach { aaptFile ->
            if (aaptFile.exists()) {
                logger.debug("dProtect: aapt rules = $aaptFile")
                proguardTask.configuration(aaptFile)
            }
        }

        // ── Mapping / seeds / usage output ──
        mappingFile.get().asFile.parentFile.mkdirs()
        proguardTask.printmapping(mappingFile.get().asFile)
        proguardTask.printseeds(seedsFile.get().asFile)
        proguardTask.printusage(usageFile.get().asFile)

        // ── Run ProGuard in Android mode ──
        proguardTask.android()
        proguardTask.proguard()

        logger.lifecycle("dProtect: Obfuscation complete. Output: $outputFile")
        logger.lifecycle("dProtect: Mapping file: ${mappingFile.get().asFile}")
    }
}
