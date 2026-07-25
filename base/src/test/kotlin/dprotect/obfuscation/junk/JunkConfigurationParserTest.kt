/*
 * dProtect -- end-to-end wiring test for the junk-code feature.
 *
 * Proves the full user-facing chain works:
 *   DSL { junk = true; junkCount = 8 }  ->  "-obfuscate-junk,8 class **"
 *   -> ConfigurationParser -> configuration.obfuscateJunk (count = 8)
 *   -> Marker flags matching classes for junk with the correct per-target count.
 *
 * (The actual bytecode injection is covered by JunkCodeObfuscationTest.)
 */

package dprotect.obfuscation.junk

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import proguard.AppView
import proguard.resources.file.ResourceFilePool
import proguard.classfile.AccessConstants
import proguard.classfile.ClassPool
import proguard.classfile.editor.ClassBuilder
import proguard.classfile.visitor.ClassVersionSetter
import proguard.classfile.VersionConstants.CLASS_VERSION_1_5
import proguard.io.ExtraDataEntryNameMap
import java.io.File
import java.util.Properties

class JunkConfigurationParserTest : io.kotest.core.spec.style.FreeSpec({

    fun parseJunkConfig(directive: String): dprotect.Configuration {
        val configuration = dprotect.Configuration()
        val baseDir = File.createTempFile("dprotect", "").parentFile
        val parser = dprotect.ConfigurationParser(directive, "test", baseDir, Properties())
        parser.parse(configuration)
        return configuration
    }

    "Given the -obfuscate-junk directive with a count modifier" - {
        "the ConfigurationParser stores the per-target count" {
            val configuration = parseJunkConfig("-obfuscate-junk,8 class **\n")

            configuration.obfuscateJunk shouldNotBe null
            configuration.obfuscateJunk.size shouldBe 1
            configuration.obfuscateJunk[0].count shouldBe 8
        }

        "the Marker flags matching classes for junk with the right count" {
            val configuration = parseJunkConfig("-obfuscate-junk,8 class **\n")

            val clazz = ClassBuilder(AccessConstants.PUBLIC, 0, "App", "java/lang/Object").programClass
            clazz.accept(ClassVersionSetter(CLASS_VERSION_1_5))
            val programClassPool = ClassPool(clazz)
            val libraryClassPool = ClassPool()

            val marker = dprotect.obfuscation.Marker(configuration)
            shouldNotThrowAny {
                marker.execute(AppView(programClassPool, libraryClassPool, ResourceFilePool(), ExtraDataEntryNameMap()))
            }

            val info = dprotect.obfuscation.info.ObfuscationInfo.getObfuscationInfo(clazz)
            info.junk shouldBe true
            info.junkCount shouldBe 8
        }
    }

    "Given the -obfuscate-junk directive without a count modifier" - {
        "the per-target count defaults to the global junkCount" {
            val configuration = parseJunkConfig("-obfuscate-junk class **\n")

            configuration.obfuscateJunk shouldNotBe null
            configuration.obfuscateJunk.size shouldBe 1
            // Global default is 3 (see Configuration.junkCount).
            configuration.obfuscateJunk[0].count shouldBe 3
        }
    }
})
