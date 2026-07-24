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

package proguard.gradle.plugin

import com.android.build.gradle.BaseExtension
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import proguard.gradle.plugin.android.AndroidPlugin
import proguard.gradle.plugin.android.AndroidProjectType

/**
 * Entry point for the dProtect/ProGuard Gradle plugin.
 *
 * Detects whether the project is an Android application or library,
 * then delegates to [AndroidPlugin] which uses the AGP 8.0+ ScopedArtifacts API.
 */
class ProGuardPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val androidExtension: BaseExtension? =
            project.extensions.findByName("android") as? BaseExtension
        val javaExtension = project.extensions.findByName("java")

        val javaErrMessage = """
            |For Java projects, you can manually declare a ProGuardTask instead of applying the plugin:
            |
            |     task myProguardTask(type: proguard.gradle.ProGuardTask) {
            |       // ...
            |     }
        """.trimMargin()

        when {
            androidExtension != null -> {
                // AGP 7.0+ is required for AndroidComponentsExtension + ScopedArtifacts API.
                // The AndroidPlugin will verify this by looking up AndroidComponentsExtension.
                val projectType = determineProjectType(project)
                AndroidPlugin(androidExtension, projectType).apply(project)
            }
            javaExtension != null -> {
                throw GradleException(
                    """
                    |The dProtect/ProGuard plugin requires the Android plugin to function properly.
                    |$javaErrMessage
                    """.trimMargin(),
                )
            }
            else -> {
                throw GradleException(
                    """
                    |For Android applications or libraries 'com.android.application' or
                    |'com.android.library' is required, respectively.
                    |$javaErrMessage
                    """.trimMargin(),
                )
            }
        }
    }

    /**
     * Determines whether the project is an Android application or library
     * by checking which AGP plugin is applied.
     */
    private fun determineProjectType(project: Project): AndroidProjectType {
        return when {
            project.plugins.hasPlugin("com.android.application") -> AndroidProjectType.ANDROID_APPLICATION
            project.plugins.hasPlugin("com.android.library") -> AndroidProjectType.ANDROID_LIBRARY
            else -> throw GradleException(
                "The dProtect/ProGuard plugin can only be used on Android application and library projects. " +
                    "Apply 'com.android.application' or 'com.android.library' before this plugin.",
            )
        }
    }
}
