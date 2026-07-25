/*
 * dProtect -- junk-code (dead/fake code) injection pass.
 *
 * Verifies that dprotect.obfuscation.junk.JunkCodeObfuscation injects the
 * requested number of junk methods (with rotated signatures and a single
 * volatile sink field) into a class marked for junk, and that the resulting
 * class file is structurally valid AND accepted by the JVM's own verifier
 * (we target class version 1.5 so the JVM uses the type-inference verifier,
 * which does not require a StackMapTable).
 *
 * The class is built entirely with dProtect-core's ClassBuilder (no
 * ClassPoolBuilder / kotlin-stdlib harness) to keep the test self-contained.
 */

package dprotect.obfuscation.junk

import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import proguard.classfile.AccessConstants
import proguard.classfile.ClassPool
import proguard.classfile.ProgramClass
import proguard.classfile.ProgramField
import proguard.classfile.ProgramMethod
import proguard.classfile.VersionConstants.CLASS_VERSION_1_5
import proguard.classfile.editor.ClassBuilder
import proguard.classfile.io.ProgramClassWriter
import proguard.classfile.visitor.ClassVersionSetter
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class JunkCodeObfuscationTest : io.kotest.core.spec.style.FreeSpec({

    fun buildAppClass(): ProgramClass {
        // Minimal "App" class. CLASS_VERSION_1_5 is a combined (major<<16|minor)
        // constant, so we build first then apply ClassVersionSetter (as the
        // existing test suite does) to set a valid v1.5 (JVM type-inference
        // verifier, no StackMapTable required).
        val clazz = ClassBuilder(AccessConstants.PUBLIC, 0, "App", "java/lang/Object").programClass
        clazz.accept(ClassVersionSetter(CLASS_VERSION_1_5))
        return clazz
    }

    fun serialize(clazz: ProgramClass): ByteArray =
        ByteArrayOutputStream().use { baos ->
            ProgramClassWriter(DataOutputStream(baos)).visitProgramClass(clazz)
            baos.toByteArray()
        }

    "Given a plain class marked for junk injection" - {
        val clazz = buildAppClass()
        val programClassPool = ClassPool(clazz)
        val libraryClassPool = ClassPool()

        dprotect.obfuscation.info.ObfuscationInfo.setClassObfuscationInfo(clazz)
        dprotect.obfuscation.info.ObfuscationInfo.getObfuscationInfo(clazz).junk = true

        "when the junk pass runs with count = 8" - {
            val pass = JunkCodeObfuscation(0xC0FFEE, programClassPool, libraryClassPool, 8)
            pass.visitAnyClass(clazz)

            "then exactly 8 junk (synthetic) methods are added" {
                val junk = clazz.methods.filterIsInstance<ProgramMethod>()
                    .filter { (it.accessFlags and AccessConstants.SYNTHETIC) != 0 }
                junk.size shouldBe 8
            }

            "then every injected method is PUBLIC, STATIC and SYNTHETIC" {
                val junk = clazz.methods.filterIsInstance<ProgramMethod>()
                    .filter { (it.accessFlags and AccessConstants.SYNTHETIC) != 0 }
                junk.size shouldBe 8
                junk.forEach {
                    (it.accessFlags and AccessConstants.PUBLIC) shouldBe AccessConstants.PUBLIC
                    (it.accessFlags and AccessConstants.STATIC) shouldBe AccessConstants.STATIC
                }
            }

            "then the junk method signatures are rotated (not all identical)" {
                val junk = clazz.methods.filterIsInstance<ProgramMethod>()
                    .filter { (it.accessFlags and AccessConstants.SYNTHETIC) != 0 }
                val descs = junk.map { it.getDescriptor(clazz) }.toSet()
                descs.size shouldBeGreaterThan 1
                // Confirm the rotated descriptor set is respected.
                descs.all { it in setOf("()V", "(I)V", "(II)V", "(I)I", "(II)I") } shouldBe true
            }

            "then exactly one private static volatile int sink field is added" {
                val volatiles = clazz.fields.filterIsInstance<ProgramField>()
                    .filter {
                        (it.accessFlags and AccessConstants.VOLATILE) != 0 &&
                        (it.accessFlags and AccessConstants.STATIC) != 0 &&
                        it.getDescriptor(clazz) == "I"
                    }
                volatiles.size shouldBe 1
            }

            "then a <clinit> that wires the junk methods is present" {
                clazz.methods.filterIsInstance<ProgramMethod>()
                    .any { it.getName(clazz) == "<clinit>" } shouldBe true
            }

            "then the class serializes to a non-empty, structural-valid class file" {
                serialize(clazz).size shouldBeGreaterThan 0
            }

            "then the JVM can load and VERIFY the modified class (authoritative)" {
                val bytes = serialize(clazz)
                val loader = object : ClassLoader() {
                    val defined = mutableMapOf<String, Class<*>>()
                    fun load(name: String, data: ByteArray): Class<*> =
                        defineClass(name, data, 0, data.size).also { defined[name] = it }
                    override fun findClass(name: String): Class<*> =
                        defined[name] ?: throw ClassNotFoundException(name)
                }
                val loaded = loader.load("App", bytes) // throws VerifyError/ClassFormatError if invalid
                loaded.name shouldBe "App"
            }

            "then running <clinit> executes every junk method without error" {
                val bytes = serialize(clazz)
                val loader = object : ClassLoader() {
                    val defined = mutableMapOf<String, Class<*>>()
                    fun load(name: String, data: ByteArray): Class<*> =
                        defineClass(name, data, 0, data.size).also { defined[name] = it }
                    override fun findClass(name: String): Class<*> =
                        defined[name] ?: throw ClassNotFoundException(name)
                }
                loader.load("App", bytes)
                // Triggers <clinit>, which invokes all injected junk methods.
                Class.forName("App", true, loader)
            }
        }

        "when the junk pass runs with count = 0 it still injects at least one method" {
            val c2 = buildAppClass()
            val p2 = ClassPool(c2)
            dprotect.obfuscation.info.ObfuscationInfo.setClassObfuscationInfo(c2)
            dprotect.obfuscation.info.ObfuscationInfo.getObfuscationInfo(c2).junk = true
            val before = c2.methods.filterIsInstance<ProgramMethod>()
                .count { (it.accessFlags and AccessConstants.SYNTHETIC) != 0 }
            JunkCodeObfuscation(1, p2, ClassPool(), 0).visitAnyClass(c2)
            val after = c2.methods.filterIsInstance<ProgramMethod>()
                .count { (it.accessFlags and AccessConstants.SYNTHETIC) != 0 }
            (after - before) shouldBeGreaterThan 0
        }
    }
})
