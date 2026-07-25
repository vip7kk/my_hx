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
 * with this program; if not to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package proguard.gradle.plugin.android.dsl

import org.gradle.api.Action

/**
 * Configurable dProtect obfuscation block for the [ProGuardAndroidExtension].
 *
 * <p>Usage (Groovy):
 * <pre>
 * dProtect {
 *     obfuscation {
 *         junk         = true          // inject junk (dead) code
 *         junkCount    = 8             // junk methods per matched class
 *         target       = "class **"    // which classes get junk-injected
 *         // strength drives defaults: strength &gt;= 3 enables junk
 *         strength     = 0
 *     }
 *     configurations { ... }
 * }
 * </pre>
 *
 * <p>The <b>junk-code</b> pass is emitted by this block as a
 * {@code -obfuscate-junk} directive. The other dProtect passes (control-flow,
 * string / arithmetic / constants) stay behind their usual {@code -obfuscate-*}
 * directives in your ProGuard rules — e.g. control-flow is enabled with
 * {@code -obfuscate-control-flow class com.example.**} written in
 * proguard-rules.pro.
 */
open class ObfuscationConfig {

    /** 0 = off (standard ProGuard only); 1..5 = increasingly aggressive. */
    var strength: Int = 0

    /**
     * Class specification targeted by the junk injection, e.g.
     * {@code "class com.example.**"} or {@code "class **"} (all app classes).
     * Only program classes are ever processed by dProtect.
     */
    var target: String = "class **"

    /**
     * Force junk-code injection on/off; null = follow [strength]
     * (junk is injected automatically when [strength] >= 3).
     */
    var junk: Boolean? = null

    /**
     * Number of junk (dead) methods injected per matched class.
     * {@code 0} (default) means "derive from [strength]":
     * 3 -> 3, 4 -> 6, 5 -> 10. Only used when junk injection is enabled.
     */
    var junkCount: Int = 0

    /**
     * Override the class target for the <b>junk</b> pass only; null = use the
     * shared [target].
     *
     * <p>Prefer this flat property over {@code junkPass { target = ... }} in
     * Groovy: inside a nested closure Groovy resolves a bare {@code target =}
     * against the outer [ObfuscationConfig.target] delegate, silently narrowing
     * the whole obfuscation target instead of just this pass.
     */
    var junkTarget: String? = null

    /** Groovy/Kotlin DSL entry point: {@code obfuscation { ... } }. */
    fun junkPass(action: Action<in JunkPassConfig>) { action.execute(junkConfig) }

    /** Per-pass configuration for the junk code injection. */
    val junkConfig: JunkPassConfig = JunkPassConfig()

    /** Whether junk code should be injected given the current settings. */
    fun isJunkEnabled(): Boolean = junk ?: (strength >= 3)

    /** Effective number of junk methods per class. */
    fun effectiveJunkCount(): Int {
        if (junkCount > 0) return junkCount
        return when (strength) {
            3 -> 3
            4 -> 6
            5 -> 10
            else -> 3
        }
    }
}

/** Per-pass configuration for the junk-code injection. */
open class JunkPassConfig {
    /** Override the class target for this pass only. Null = use the parent target. */
    var target: String? = null
    /** Override the per-class junk-method count for this pass only. 0 = parent default. */
    var count: Int = 0
}
