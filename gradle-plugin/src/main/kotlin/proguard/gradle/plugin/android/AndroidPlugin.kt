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

package proguard.gradle.plugin.android

import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.api.variant.ScopedArtifacts
import com.android.build.gradle.BaseExtension
import java.io.File
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.artifacts.Configuration
import org.gradle.api.attributes.Attribute
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.TaskProvider
import proguard.gradle.plugin.android.AndroidProjectType.ANDROID_APPLICATION
import proguard.gradle.plugin.android.AndroidProjectType.ANDROID_LIBRARY
import proguard.gradle.plugin.android.dsl.ProGuardAndroidExtension
import proguard.gradle.plugin.android.dsl.ProGuardConfiguration
import proguard.gradle.plugin.android.dsl.UserProGuardConfiguration
import proguard.gradle.plugin.android.dsl.VariantConfiguration
import proguard.gradle.plugin.android.tasks.CollectConsumerRulesTask
import proguard.gradle.plugin.android.tasks.ConsumerRuleFilterEntry
import proguard.gradle.plugin.android.tasks.PrepareProguardConfigDirectoryTask
import proguard.gradle.plugin.android.tasks.ProGuardAndroidTask
import proguard.gradle.plugin.android.transforms.AndroidConsumerRulesTransform
import proguard.gradle.plugin.android.transforms.ArchiveConsumerRulesTransform

/**
 * Android plugin entry point for dProtect/ProGuard.
 *
 * In AGP 8.0+, the Transform API ([com.android.build.api.transform.Transform]) was
 * removed. This plugin now uses the [ScopedArtifacts] API ([ScopedArtifact.CLASSES])
 * to intercept all compiled classes and run ProGuard obfuscation via [ProGuardAndroidTask].
 *
 * The high-level flow for each variant:
 * 1. [configureAapt] — ensures AAPT generates keep rules for ProGuard.
 * 2. Consumer rules are collected from the variant's runtime configuration via
 *    [CollectConsumerRulesTask] (unchanged from the original implementation).
 * 3. [ProGuardAndroidTask] is registered via [ScopedArtifacts.forScope] + [toTransform]
 *    to replace all compiled classes with ProGuard's obfuscated output.
 * 4. Library jars (android.jar, provided-only / external dependencies) are wired
 *    to the task for ProGuard's classpath resolution.
 */
class AndroidPlugin(
    private val androidExtension: BaseExtension,
    private val projectType: AndroidProjectType,
) : Plugin<Project> {

    override fun apply(project: Project) {
        val proguardBlock =
            project.extensions.create("dProtect", ProGuardAndroidExtension::class.java, project)

        // 1. Configure AAPT to generate ProGuard keep rules.
        configureAapt(project)

        // 2. Register dependency transforms for consumer rule extraction (unchanged).
        registerDependencyTransforms(project)

        // 3. Prepare the consumer-rules collection task (shared).
        val collectConsumerRulesTask =
            project.tasks.register(COLLECT_CONSUMER_RULES_TASK_NAME)

        // 4. Determine the scope: apps obfuscate ALL classes (project + sub + ext);
        //    libraries obfuscate only PROJECT classes.
        val scope =
            if (projectType == ANDROID_APPLICATION) {
                ScopedArtifacts.Scope.ALL
            } else {
                ScopedArtifacts.Scope.PROJECT
            }

        // 5. Get the AndroidComponentsExtension (AGP 7.0+ new variant API).
        val androidComponents =
            project.extensions.findByType(AndroidComponentsExtension::class.java)
                ?: throw GradleException(
                    "AndroidComponentsExtension not found. dProtect requires AGP 7.0+ (recommended 8.0+).",
                )

        // 6. Register a ProGuard task for each variant that has a matching configuration.
        androidComponents.onVariants { variant ->
            val variantName = variant.name
            val matchingConfiguration = proguardBlock.configurations.findVariantConfiguration(variantName)

            if (matchingConfiguration != null) {

                // Verify minify is disabled (ProGuard/dProtect handles obfuscation).
                verifyNotMinified(project, variantName, androidExtension)

                // Prepare the proguard config directory task (already registered in configureAapt).
                val prepareConfigDirTask =
                    project.tasks.named(
                        "prepareProguardConfigDirectory",
                        PrepareProguardConfigDirectoryTask::class.java,
                    )

                // ── Consumer rules collection ──
                val consumerRulesConfig = createConsumerRulesConfiguration(project, variantName)
                val collectTaskName = COLLECT_CONSUMER_RULES_TASK_NAME + variantName.replaceFirstChar { it.uppercase() }
                val consumerRulesOutputDir =
                    project.buildDir.resolve("intermediates/proguard/configs")

                val collectTask =
                    project.tasks.register(
                        collectTaskName,
                        CollectConsumerRulesTask::class.java,
                    ) { task ->
                        task.consumerRulesConfiguration = consumerRulesConfig
                        task.consumerRuleFilter =
                            parseConsumerRuleFilter(matchingConfiguration.consumerRuleFilter)
                        task.outputFile =
                            File(
                                File(consumerRulesOutputDir, variantName),
                                CONSUMER_RULES_PRO,
                            )
                    }

                collectConsumerRulesTask.configure { it.dependsOn(collectTask) }

                // ── ProGuard obfuscation task ──
                val taskName = "proguard" + variantName.replaceFirstChar { it.uppercase() }
                val taskProvider =
                    project.tasks.register(taskName, ProGuardAndroidTask::class.java) { task ->
                        task.variantName.set(variantName)

                        // Configuration files (user .pro rules).
                        task.configurationFiles.from(
                            matchingConfiguration.configurations.map { project.file(it.path) },
                        )

                        // Consumer rules output (depends on collection task).
                        task.consumerRules.from(collectTask.map { it.outputs.files })
                        task.dependsOn(collectTask)

                        // AAPT rules (may not exist yet at configuration time).
                        task.aaptRules.from(
                            project.provider {
                                val aaptFile = getAaptRulesFile()
                                if (aaptFile != null && File(aaptFile).exists()) {
                                    project.files(aaptFile)
                                } else {
                                    project.files()
                                }
                            },
                        )

                        // Library jars.
                        task.libraryJars.from(createLibraryJars(project, variantName))

                        // Mapping / seeds / usage output.
                        val outputDir =
                            project.buildDir.resolve("outputs/proguard/$variantName/mapping")
                        if (!outputDir.exists()) {
                            outputDir.mkdirs()
                        }
                        task.mappingFile.set(File(outputDir, "mapping.txt"))
                        task.seedsFile.set(File(outputDir, "seeds.txt"))
                        task.usageFile.set(File(outputDir, "usage.txt"))

                        // Output location (will be set by ScopedArtifacts).
                        task.output.set(
                            project.buildDir.resolve(
                                "intermediates/proguard/$variantName/obfuscated.jar",
                            ),
                        )
                    }

                // ── Wire via ScopedArtifacts: replaces all compiled classes with obfuscated output ──
                variant.artifacts
                    .forScope(scope)
                    .use(taskProvider)
                    .toTransform(
                        ScopedArtifact.CLASSES,
                        { task -> task.allJars },
                        { task -> task.allDirs },
                        { task -> task.output },
                    )

                taskProvider.configure { task ->
                    task.dependsOn(prepareConfigDirTask)
                }
            }
        }

        // 7. After evaluation, verify configuration files exist.
        //    NOTE: We intentionally do NOT validate "unmatched variants" here.
        //    In AGP 8.0+, the onVariants callback fires AFTER afterEvaluate,
        //    so matchedConfigurations would always be empty at this point,
        //    causing false "variant does not exist" errors.
        project.afterEvaluate {
            if (proguardBlock.configurations.isEmpty()) {
                throw GradleException("There are no configured variants in the 'dProtect' block")
            }

            // Verify that user-specified configuration files exist.
            proguardBlock.configurations.forEach { config ->
                config.configurations.filterIsInstance<UserProGuardConfiguration>().forEach {
                    val file = project.file(it.path)
                    if (!file.exists()) {
                        throw GradleException("ProGuard configuration file ${file.absolutePath} was set but does not exist.")
                    }
                }
            }
        }
    }

    // ──────────────────────────────────────────────
    // AAPT configuration
    // ──────────────────────────────────────────────

    private fun configureAapt(project: Project) {
        val aaptRulesDir = project.buildDir.resolve("intermediates/proguard/configs")
        val createDirectoryTask =
            project.tasks.register(
                "prepareProguardConfigDirectory",
                PrepareProguardConfigDirectoryTask::class.java,
            )

        // Create the directory eagerly at configuration time so AAPT can find it
        // when it runs during resource processing (e.g. processDebugResources).
        if (!aaptRulesDir.exists()) {
            aaptRulesDir.mkdirs()
        }

        // Add AAPT flags to generate ProGuard keep rules.
        val aaptParams = androidExtension.aaptAdditionalParameters
        if (!aaptParams.contains("--proguard")) {
            aaptParams.addAll(
                listOf(
                    "--proguard",
                    aaptRulesDir.resolve("aapt_rules.pro").absolutePath,
                ),
            )
        }
        if (!aaptParams.contains("--proguard-conditional-keep-rules")) {
            aaptParams.add("--proguard-conditional-keep-rules")
        }
    }

    // ──────────────────────────────────────────────
    // Consumer rules
    // ──────────────────────────────────────────────

    private fun createConsumerRulesConfiguration(project: Project, variantName: String): Configuration {
        val configName = "${variantName}ProGuardConsumerRulesArtifacts"
        // Remove if it already exists (can happen on re-evaluation).
        project.configurations.findByName(configName)?.let { project.configurations.remove(it) }

        val runtimeConfig = project.configurations.findByName("${variantName}RuntimeClasspath")
            ?: project.configurations.findByName("runtimeClasspath")

        return project.configurations.create(configName) { config ->
            config.isCanBeResolved = true
            config.isCanBeConsumed = false
            config.isTransitive = true

            runtimeConfig?.let { config.extendsFrom(it) }

            config.attributes.attribute(ATTRIBUTE_ARTIFACT_TYPE, ARTIFACT_TYPE_CONSUMER_RULES)
        }
    }

    private fun parseConsumerRuleFilter(consumerRuleFilter: List<String>): List<ConsumerRuleFilterEntry> =
        consumerRuleFilter.map { filter ->
            val splits = filter.split(':')
            if (splits.size != 2) {
                throw GradleException(
                    "Invalid consumer rule filter entry: $filter\nExpected an entry of the form: <group>:<module>",
                )
            }
            ConsumerRuleFilterEntry(splits[0], splits[1])
        }

    // ──────────────────────────────────────────────
    // Library jars
    // ──────────────────────────────────────────────

    /**
     * Creates the set of library jars for ProGuard's classpath resolution.
     *
     * - Apps (Scope.ALL): only provided-only deps + android.jar are library jars
     *   (everything else is in injars).
     * - Libraries (Scope.PROJECT): external + sub-project deps + android.jar are library jars
     *   (only project classes are in injars).
     */
    private fun createLibraryJars(project: Project, variantName: String): Any {
        val files = project.files()

        // android.jar from SDK
        val androidJar =
            androidExtension.sdkDirectory
                ?.resolve("platforms/${androidExtension.compileSdkVersion}/android.jar")
        if (androidJar != null && androidJar.exists()) {
            files.from(androidJar)
        }

        // Optional platform libraries
        try {
            androidExtension.libraryRequests.forEach { libRequest ->
                val optionalJar =
                    androidExtension.sdkDirectory
                        ?.resolve(
                            "platforms/${androidExtension.compileSdkVersion}/optional/${libRequest.name}.jar",
                        )
                if (optionalJar != null && optionalJar.exists()) {
                    files.from(optionalJar)
                }
            }
        } catch (e: Exception) {
            project.logger.debug("dProtect: Could not access libraryRequests: ${e.message}")
        }

        // Runtime/provided dependencies as library jars
        when (projectType) {
            ANDROID_APPLICATION -> {
                // For apps, external+sub are in injars (ALL scope).
                // Only compileOnly (provided) deps are library jars.
                // In Gradle 8.x, 'compileOnly' has canBeResolved=false, so we
                // create a resolvable configuration that extends it.
                val providedConfigName = "dprotect${variantName.replaceFirstChar { it.uppercase() }}Provided"
                project.configurations.findByName(providedConfigName)?.let { project.configurations.remove(it) }
                val providedConfig = project.configurations.create(providedConfigName) { config ->
                    config.isCanBeResolved = true
                    config.isCanBeConsumed = false
                    config.isTransitive = true
                    project.configurations.findByName("compileOnly")?.let { config.extendsFrom(it) }
                }
                files.from(providedConfig)
            }
            ANDROID_LIBRARY -> {
                // For libraries, external+sub are library jars (only PROJECT is in injars).
                val runtimeConfig =
                    project.configurations.findByName("${variantName}RuntimeClasspath")
                        ?: project.configurations.findByName("runtimeClasspath")
                runtimeConfig?.let { files.from(it) }
            }
        }

        return files
    }

    // ──────────────────────────────────────────────
    // Dependency transforms (unchanged from original)
    // ──────────────────────────────────────────────

    private fun registerDependencyTransforms(project: Project) {
        project.dependencies.registerTransform(ArchiveConsumerRulesTransform::class.java) {
            it.from.attribute(ATTRIBUTE_ARTIFACT_TYPE, "aar")
            it.to.attribute(ATTRIBUTE_ARTIFACT_TYPE, ARTIFACT_TYPE_CONSUMER_RULES)
        }
        project.dependencies.registerTransform(ArchiveConsumerRulesTransform::class.java) {
            it.from.attribute(ATTRIBUTE_ARTIFACT_TYPE, "jar")
            it.to.attribute(ATTRIBUTE_ARTIFACT_TYPE, ARTIFACT_TYPE_CONSUMER_RULES)
        }
        project.dependencies.registerTransform(AndroidConsumerRulesTransform::class.java) {
            it.from.attribute(ATTRIBUTE_ARTIFACT_TYPE, "android-consumer-proguard-rules")
            it.to.attribute(ATTRIBUTE_ARTIFACT_TYPE, ARTIFACT_TYPE_CONSUMER_RULES)
        }
    }

    // ──────────────────────────────────────────────
    // Utility
    // ──────────────────────────────────────────────

    private fun verifyNotMinified(project: Project, variantName: String, androidExtension: BaseExtension) {
        try {
            // Try to find the build type and check minifyEnabled.
            val buildTypeName = variantName.substringAfterLast("Debug").substringAfterLast("Release")
            // This is a best-effort check; if we can't determine minify status, skip.
            val buildTypes = androidExtension.buildTypes
            for (buildType in buildTypes) {
                if (variantName.lowercase().contains(buildType.name.lowercase())) {
                    if (buildType.isMinifyEnabled) {
                        throw GradleException(
                            "The option 'minifyEnabled' is set to 'true' for variant '$variantName', " +
                                "but should be 'false' for variants processed by dProtect/ProGuard. " +
                                "Set minifyEnabled false in your build type configuration.",
                        )
                    }
                }
            }
        } catch (e: GradleException) {
            throw e
        } catch (e: Exception) {
            project.logger.debug("dProtect: Could not verify minify status for $variantName: ${e.message}")
        }
    }

    private fun getAaptRulesFile(): String? {
        val params = androidExtension.aaptAdditionalParameters
        return params
            .zipWithNext { cmd, param -> if (cmd == "--proguard") param else null }
            .filterNotNull()
            .firstOrNull()
    }

    companion object {
        const val COLLECT_CONSUMER_RULES_TASK_NAME = "collectConsumerRules"

        private const val CONSUMER_RULES_PRO = "consumer-rules.pro"
        private const val ARTIFACT_TYPE_CONSUMER_RULES = "proguard-consumer-rules"
        private val ATTRIBUTE_ARTIFACT_TYPE = Attribute.of("artifactType", String::class.java)
    }
}

enum class AndroidProjectType {
    ANDROID_APPLICATION,
    ANDROID_LIBRARY,
}

// ──────────────────────────────────────────────────────────────────
// Variant configuration matching helpers
// ──────────────────────────────────────────────────────────────────

fun Iterable<VariantConfiguration>.findVariantConfiguration(variantName: String): VariantConfiguration? =
    find { it.name == variantName } ?: find { variantName.endsWith(it.name.replaceFirstChar { c -> c.uppercase() }) }

fun Iterable<VariantConfiguration>.hasVariantConfiguration(variantName: String): Boolean =
    findVariantConfiguration(variantName) != null

/**
 * Extension property that wraps the aapt additional parameters.
 *
 * In AGP 7.0+, [BaseExtension.getAaptOptions] was replaced by [BaseExtension.getAndroidResources].
 * Since dProtect requires AGP 7.0+ (recommended 8.0+), we always use [getAndroidResources].
 */
@Suppress("UNCHECKED_CAST")
val BaseExtension.aaptAdditionalParameters: MutableCollection<String>
    get() {
        val aaptOptions = this.javaClass.methods.first { it.name == "getAndroidResources" }.invoke(this)
        val additionalParameters =
            aaptOptions.javaClass.methods.first { it.name == "getAdditionalParameters" }.invoke(aaptOptions)
        return if (additionalParameters != null) {
            additionalParameters as MutableCollection<String>
        } else {
            val newAdditionalParameters = ArrayList<String>()
            aaptOptions
                .javaClass
                .methods
                .first { it.name == "setAdditionalParameters" }
                .invoke(aaptOptions, newAdditionalParameters)
            newAdditionalParameters
        }
    }
