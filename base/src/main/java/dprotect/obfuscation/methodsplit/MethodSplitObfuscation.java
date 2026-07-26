package dprotect.obfuscation.methodsplit;

import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import proguard.classfile.*;
import proguard.classfile.attribute.*;
import proguard.classfile.attribute.visitor.AttributeVisitor;
import proguard.classfile.editor.*;
import proguard.classfile.visitor.ClassVisitor;
import proguard.util.ProcessingFlags;

import dprotect.obfuscation.info.ObfuscationInfo;

/**
 * Method-splitting pass ("rename-based trampoline").
 *
 * <h2>Goal</h2>
 * De-correlate the shipped bytecode from the original source structure by
 * turning every eligible method {@code N} of a flagged class into <em>two</em>
 * methods:
 * <ol>
 *   <li>the original body, kept <em>byte-for-byte</em> but <b>renamed in place</b>
 *       to a fresh random identifier {@code N'} and demoted to {@code private}
 *       (plus {@code synthetic}); and</li>
 *   <li>a brand-new same-name/same-descriptor forwarding stub {@code N} that
 *       simply loads {@code this} + all parameters and tail-calls {@code N'}.</li>
 * </ol>
 * Every original call site (internal or from another class) keeps referring to
 * {@code N} — which now resolves to the tiny stub — so behaviour is identical,
 * while the class gains an extra layer of indirection and its member table no
 * longer maps 1:1 onto the source methods.
 *
 * <h2>Why rename-based instead of branch-extraction?</h2>
 * dProtect's optimizer (which contains the method inliner) runs <em>before</em>
 * {@code CodeObfuscator}; after this pass only shrinking and <em>name</em>
 * obfuscation remain. A rename-based split therefore cannot be inlined back
 * together by the optimizer (unlike a body-extraction split, which the inliner
 * would happily fold — the exact trap the control-flow pass hit earlier). It is
 * also zero-copy: the real body's {@code Code} attribute, exception table, line
 * numbers and local-variable tables are untouched, so there is no risk of
 * producing unverifiable bytecode.
 *
 * <h2>Safety</h2>
 * <ul>
 *   <li>Interfaces are skipped entirely.</li>
 *   <li>{@code <init>} / {@code <clinit>} are never touched.</li>
 *   <li>{@code abstract} / {@code native} methods (no {@code Code}) are skipped.</li>
 *   <li>{@code synthetic} / {@code bridge} compiler artifacts are skipped.</li>
 *   <li>Any method carrying {@link ProcessingFlags#DONT_OBFUSCATE} (i.e. a
 *       {@code -keep}-protected entry point, lifecycle callback, reflected,
 *       serialized or enum method) is skipped — those must retain both their
 *       exact name and their exact single-method identity.</li>
 * </ul>
 * Because the stub keeps the original name and signature, framework virtual
 * dispatch, overrides and {@code super} calls all continue to resolve to the
 * stub, which then forwards to the real body — so even non-kept overrides of
 * framework methods remain correct.
 *
 * <p>The {@link proguard.classfile.util.ClassReferenceInitializer} run at the
 * tail of {@link dprotect.obfuscation.CodeObfuscator} re-links every
 * {@code Methodref} by name, so the stub's freshly-created reference to the
 * renamed body is resolved together with all the pre-existing references to the
 * (now stub) original name.</p>
 */
public class MethodSplitObfuscation
implements   ClassVisitor
{
    private static final Logger logger = LogManager.getLogger(MethodSplitObfuscation.class);

    /**
     * Methods whose real body is shorter than this (in bytes) are left alone:
     * trivial getters/setters gain almost no structural diversity from a split
     * yet would roughly double the app-wide method count.
     */
    private static final int MIN_CODE_LENGTH = 6;

    private final Random    rand;
    private final ClassPool programClassPool;
    private final ClassPool libraryClassPool;

    /** Number of methods actually split (for the summary log). */
    private int splitCount;

    public MethodSplitObfuscation(int       seed,
                                  ClassPool programClassPool,
                                  ClassPool libraryClassPool)
    {
        this.rand             = new Random((long)seed);
        this.programClassPool = programClassPool;
        this.libraryClassPool = libraryClassPool;
    }

    public int getSplitCount()
    {
        return splitCount;
    }

    // Implementations for ClassVisitor.

    @Override
    public void visitAnyClass(Clazz clazz)
    {
        if (clazz instanceof ProgramClass)
        {
            visitProgramClass((ProgramClass)clazz);
        }
    }

    public void visitProgramClass(ProgramClass programClass)
    {
        // Splitting methods of an interface makes no sense (default/abstract only).
        if ((programClass.getAccessFlags() & AccessConstants.INTERFACE) != 0)
        {
            return;
        }

        if (!ObfuscationInfo.getObfuscationInfo(programClass).methodSplit)
        {
            return;
        }

        ConstantPoolEditor constantPoolEditor = new ConstantPoolEditor(programClass);
        ClassBuilder       classBuilder       =
            new ClassBuilder(programClass, programClassPool, libraryClassPool);

        // Snapshot the original method table: we append stubs while iterating,
        // so we must not walk the growing array.
        int             originalCount = programClass.u2methodsCount;
        ProgramMethod[] snapshot      = new ProgramMethod[originalCount];
        System.arraycopy(programClass.methods, 0, snapshot, 0, originalCount);

        for (ProgramMethod method : snapshot)
        {
            if (!isEligible(programClass, method))
            {
                continue;
            }

            splitMethod(programClass, method, constantPoolEditor, classBuilder);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Core
    // ──────────────────────────────────────────────────────────────

    private boolean isEligible(ProgramClass programClass, ProgramMethod method)
    {
        String name = method.getName(programClass);

        // Never touch the initializers.
        if (name.equals("<init>") || name.equals("<clinit>"))
        {
            return false;
        }

        int flags = method.u2accessFlags;

        // No Code attribute to forward to.
        if ((flags & (AccessConstants.ABSTRACT | AccessConstants.NATIVE)) != 0)
        {
            return false;
        }

        // Compiler artifacts: leave dispatch semantics intact.
        if ((flags & (AccessConstants.SYNTHETIC | AccessConstants.BRIDGE)) != 0)
        {
            return false;
        }

        // -keep protected: entry points, lifecycle, reflection, serialization,
        // enum values()/valueOf(), etc. must keep their exact identity + name.
        if ((method.getProcessingFlags() & ProcessingFlags.DONT_OBFUSCATE) != 0)
        {
            return false;
        }

        // Skip trivial bodies (and defensively anything without a Code attribute).
        int codeLength = codeLength(programClass, method);
        if (codeLength < MIN_CODE_LENGTH)
        {
            return false;
        }

        return true;
    }

    private void splitMethod(ProgramClass       programClass,
                             ProgramMethod      realMethod,
                             ConstantPoolEditor constantPoolEditor,
                             ClassBuilder       classBuilder)
    {
        // Capture the original public identity BEFORE mutating the method.
        final String origName  = realMethod.getName(programClass);
        final String origDesc  = realMethod.getDescriptor(programClass);
        final int    origFlags = realMethod.u2accessFlags;
        final boolean isStatic = (origFlags & AccessConstants.STATIC) != 0;

        // 1) Rename the real body in place to a fresh private identifier.
        String newName = nextMethodName(programClass, origDesc);
        int    nameIndex = constantPoolEditor.addUtf8Constant(newName);
        realMethod.u2nameIndex = nameIndex;

        // Demote to private + synthetic, keeping static/final/synchronized/etc.
        int realFlags = (origFlags & ~(AccessConstants.PUBLIC | AccessConstants.PROTECTED))
                        | AccessConstants.PRIVATE
                        | AccessConstants.SYNTHETIC;
        realMethod.u2accessFlags = realFlags;

        // 2) Add the same-name/same-descriptor forwarding stub. It keeps the
        //    original access flags (minus SYNCHRONIZED — the real body still
        //    holds the monitor, so the stub need not).
        int stubFlags = origFlags & ~AccessConstants.SYNCHRONIZED;

        int paramSlots = parameterSlots(origDesc, isStatic);
        int maxFragment = Math.max(16, paramSlots * 3 + 12);

        classBuilder.addMethod(
            stubFlags,
            origName,
            origDesc,
            maxFragment,
            ____ -> buildForwardingBody(____, programClass, realMethod, origDesc, isStatic));

        splitCount++;
    }

    /**
     * Emits {@code [aload_0,] <load each argument>, invoke{special|static} N', <return>}.
     */
    private void buildForwardingBody(CompactCodeAttributeComposer ____,
                                     ProgramClass                 programClass,
                                     ProgramMethod                realMethod,
                                     String                       descriptor,
                                     boolean                      isStatic)
    {
        int local = 0;

        if (!isStatic)
        {
            ____.aload(local);
            local++;
        }

        // Load every declared parameter in order.
        int i = descriptor.indexOf('(') + 1;
        while (descriptor.charAt(i) != ')')
        {
            char c = descriptor.charAt(i);
            switch (c)
            {
                case 'B': case 'C': case 'S': case 'Z': case 'I':
                    ____.iload(local);
                    local += 1;
                    i++;
                    break;
                case 'F':
                    ____.fload(local);
                    local += 1;
                    i++;
                    break;
                case 'J':
                    ____.lload(local);
                    local += 2;
                    i++;
                    break;
                case 'D':
                    ____.dload(local);
                    local += 2;
                    i++;
                    break;
                case 'L':
                    ____.aload(local);
                    local += 1;
                    i = descriptor.indexOf(';', i) + 1;
                    break;
                case '[':
                    // Skip all leading '[' then the element type.
                    int j = i;
                    while (descriptor.charAt(j) == '[') j++;
                    if (descriptor.charAt(j) == 'L')
                    {
                        j = descriptor.indexOf(';', j) + 1;
                    }
                    else
                    {
                        j++;
                    }
                    ____.aload(local);
                    local += 1;
                    i = j;
                    break;
                default:
                    // Should never happen for a well-formed descriptor.
                    i++;
                    break;
            }
        }

        // Forward to the renamed real body.
        if (isStatic)
        {
            ____.invokestatic(programClass, realMethod);
        }
        else
        {
            ____.invokespecial(programClass, realMethod);
        }

        // Return using the descriptor's return type.
        char ret = descriptor.charAt(descriptor.indexOf(')') + 1);
        switch (ret)
        {
            case 'V': ____.return_();  break;
            case 'B': case 'C': case 'S': case 'Z': case 'I': ____.ireturn(); break;
            case 'F': ____.freturn();  break;
            case 'J': ____.lreturn();  break;
            case 'D': ____.dreturn();  break;
            default:  ____.areturn();  break; // 'L' or '['
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    /** Returns the {@code Code} length of the method, or {@code -1} if it has none. */
    private int codeLength(ProgramClass programClass, ProgramMethod method)
    {
        final int[] length = { -1 };
        method.attributesAccept(programClass, new AttributeVisitor()
        {
            @Override
            public void visitAnyAttribute(Clazz clazz, Attribute attribute) { }

            @Override
            public void visitCodeAttribute(Clazz clazz, Method m, CodeAttribute codeAttribute)
            {
                length[0] = codeAttribute.u4codeLength;
            }
        });
        return length[0];
    }

    /** Total local-variable slots consumed by the (implicit this +) parameters. */
    private static int parameterSlots(String descriptor, boolean isStatic)
    {
        int slots = isStatic ? 0 : 1;
        int i = descriptor.indexOf('(') + 1;
        while (descriptor.charAt(i) != ')')
        {
            char c = descriptor.charAt(i);
            switch (c)
            {
                case 'J': case 'D':
                    slots += 2;
                    i++;
                    break;
                case 'L':
                    slots += 1;
                    i = descriptor.indexOf(';', i) + 1;
                    break;
                case '[':
                    int j = i;
                    while (descriptor.charAt(j) == '[') j++;
                    if (descriptor.charAt(j) == 'L')
                    {
                        j = descriptor.indexOf(';', j) + 1;
                    }
                    else
                    {
                        j++;
                    }
                    slots += 1;
                    i = j;
                    break;
                default: // B C S Z I F
                    slots += 1;
                    i++;
                    break;
            }
        }
        return slots;
    }

    /**
     * Generates a fresh, valid Java identifier for the renamed real body,
     * guaranteed not to collide with an existing member of the same descriptor.
     */
    private String nextMethodName(ProgramClass programClass, String descriptor)
    {
        for (int attempt = 0; attempt < 32; attempt++)
        {
            String name = "m" + Long.toHexString(Math.abs(rand.nextLong())) + "_" + attempt;
            if (programClass.findMethod(name, descriptor) == null)
            {
                return name;
            }
        }
        // Fallback: practically unreachable.
        return "m" + System.nanoTime();
    }
}
