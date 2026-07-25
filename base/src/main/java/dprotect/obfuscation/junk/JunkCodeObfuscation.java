package dprotect.obfuscation.junk;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import proguard.classfile.*;
import proguard.classfile.attribute.*;
import proguard.classfile.attribute.visitor.*;
import proguard.classfile.editor.*;
import proguard.classfile.instruction.Instruction;
import proguard.classfile.instruction.visitor.InstructionVisitor;
import proguard.classfile.visitor.*;

import dprotect.obfuscation.info.ObfuscationInfo;

/**
 * Junk-code injection pass (upgraded fork of Moosphan/app-code-obfuscation's
 * "truly-called junk methods" idea, adapted to dProtect's ProGuard pipeline).
 *
 * <h2>Two complementary layers</h2>
 * For every class flagged with {@code ObfuscationInfo.junk} this pass now runs
 * <em>two</em> distinct obfuscations, attacking different similarity vectors:
 *
 * <ol>
 *   <li><b>Polymorphic inline dead branches (primary).</b> Opaque-predicate
 *       -guarded dead-code blocks are spliced both into the <em>entry</em> and
 *       into random <em>mid-method basic-block boundaries</em> of every eligible
 *       business method. This mutates the <em>real method's own control-flow
 *       graph</em> (extra basic blocks + edges) throughout its body — not just at
 *       the head — which is exactly the fingerprint structural similarity
 *       detectors rely on. Because the guard is an opaque predicate the optimizer
 *       cannot fold, dead-code elimination cannot cleanly restore the original
 *       CFG — unlike standalone junk methods, which a caller graph analysis can
 *       simply filter out. Crucially the injection is <em>polymorphic</em>: each
 *       site draws one of several structurally-different guard shapes (via
 *       {@link #emitOpaqueGuard}) and a random combination of dead-block fragments
 *       from a pool (via {@link #emitDeadFragment}), so the junk is heterogeneous
 *       per-site rather than a single template a de-obfuscator could pattern-match
 *       and strip in bulk. Mid-method offsets are chosen only where the operand
 *       stack is provably empty (via {@link #collectSafeMidOffsets}), keeping the
 *       result verifiable.</li>
 *   <li><b>Standalone junk methods (kept, complementary).</b> {@code junkCount}
 *       brand-new {@code public static synthetic} methods are synthesized and
 *       referenced from {@code <clinit>} so they survive shrinking. These inflate
 *       the member count / bytecode volume of the class.</li>
 * </ol>
 *
 * <h2>Opaque predicate design (why it survives, why it costs nothing at runtime)</h2>
 * Each class gets a private static {@code int} invariant field {@code jo<hex>}
 * initialized in {@code <clinit>} as
 * <pre>
 *   jo = (int) System.currentTimeMillis();
 *   jo = jo * jo - jo;          // x*x - x == x*(x-1): product of two consecutive
 *                               // ints, hence ALWAYS even, but runtime-unknown.
 * </pre>
 * The optimizer cannot fold {@code jo % 2} to a constant (the seed comes from a
 * non-constant runtime source and there is no trivially-trackable bit pattern),
 * so the guarded branch is retained. At runtime {@code jo % 2 == 0} is always
 * true, so the {@code ifeq SKIP} is <em>always</em> taken and the dead block is
 * <em>never</em> executed — zero behaviour change, near-zero per-call overhead
 * (one static read + {@code irem} + branch).
 *
 * <h2>Why the volatile field + Math.random() side effect?</h2>
 * The dead block (and the standalone methods) perform a read-modify-write on a
 * {@code volatile} sink field plus a {@link Math#random()} call. These are
 * observable, non-removable side effects, so ProGuard's optimizer keeps the
 * injected instructions instead of emptying the block via dead-store elimination.
 *
 * Because everything is injected <em>after</em> dProtect's other passes have run,
 * the injected code is itself re-processed by the control-flow / arithmetic (MBA)
 * passes when those are enabled, producing a second obfuscation layer for free.
 */
public class JunkCodeObfuscation
implements   ClassVisitor,
             AttributeVisitor
{
    private static final Logger logger = LogManager.getLogger(JunkCodeObfuscation.class);

    /** Signatures rotated across the synthesized junk methods. */
    private static final String[] DESCRIPTORS = {
        "()V", "(I)V", "(II)V", "(I)I", "(II)I"
    };

    private final Random   rand;
    private final ClassPool programClassPool;
    private final ClassPool libraryClassPool;
    private final int       junkCount;

    /** Reused across the methods of the class currently being processed. */
    private final CodeAttributeEditor codeAttributeEditor = new CodeAttributeEditor();

    /**
     * Computes the operand-stack height before every instruction, so inline
     * dead branches can be spliced in <em>mid-method</em> only at offsets where
     * the stack is empty (see {@link #collectSafeMidOffsets}).
     */
    private final StackSizeComputer stackSizeComputer = new StackSizeComputer();

    /** Per-class state, set at the start of {@link #visitProgramClass}. */
    private String sinkFieldName;
    private String opaqueFieldName;

    public JunkCodeObfuscation(int       seed,
                               ClassPool programClassPool,
                               ClassPool libraryClassPool,
                               int       junkCount)
    {
        this.rand             = new Random((long)seed);
        this.programClassPool = programClassPool;
        this.libraryClassPool = libraryClassPool;
        this.junkCount        = Math.max(1, junkCount);
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
        // Junk methods make no sense on interfaces.
        if ((programClass.getAccessFlags() & AccessConstants.INTERFACE) != 0)
        {
            return;
        }

        if (!ObfuscationInfo.getObfuscationInfo(programClass).junk)
        {
            return;
        }

        // ── Per-class fields ──────────────────────────────────────────
        // One volatile sink field, shared by the dead blocks and the junk methods.
        sinkFieldName   = "jf" + Long.toHexString(Math.abs(rand.nextLong()));
        // One opaque-invariant field driving every inline dead-branch guard.
        opaqueFieldName = "jo" + Long.toHexString(Math.abs(rand.nextLong()));

        ClassBuilder classBuilder = new ClassBuilder(programClass, programClassPool, libraryClassPool);
        classBuilder.addField(
            AccessConstants.PRIVATE | AccessConstants.STATIC | AccessConstants.VOLATILE,
            sinkFieldName,
            "I");
        classBuilder.addField(
            AccessConstants.PRIVATE | AccessConstants.STATIC,
            opaqueFieldName,
            "I");

        // Initialize the opaque invariant field: jo = t*t - t (always even, runtime-unknown).
        new InitializerEditor(programClass).addStaticInitializerInstructions(
            /* mergeIntoExistingInitializer */ true,
            ____ -> ____
                .invokestatic("java/lang/System", "currentTimeMillis", "()J")
                .l2i()                 // t
                .dup()                 // t, t
                .dup()                 // t, t, t
                .imul()                // t, t*t
                .swap()                // t*t, t
                .isub()                // t*t - t
                .putstatic(programClass.getName(), opaqueFieldName, "I"));

        // ── Layer 1: inline dead branches into eligible business methods ──
        // Skip abstract/native (no Code), and synthetic methods (incl. our own
        // junk methods, which are added *after* this pass over existing methods).
        programClass.accept(new AllMethodVisitor(
                            new MemberAccessFilter(
                                0,
                                AccessConstants.ABSTRACT | AccessConstants.NATIVE | AccessConstants.SYNTHETIC | AccessConstants.BRIDGE,
                            new AllAttributeVisitor(this))));

        // ── Layer 2: standalone synthetic junk methods (kept) ──
        List<String[]> junkMethods = new ArrayList<>();

        for (int i = 0; i < junkCount; i++)
        {
            String desc = DESCRIPTORS[rand.nextInt(DESCRIPTORS.length)];
            String name = nextMethodName(programClass, desc);
            int paramCount = countIntParams(desc);

            classBuilder.addMethod(
                AccessConstants.PUBLIC | AccessConstants.STATIC | AccessConstants.SYNTHETIC,
                name,
                desc,
                /* maxStack */ 8,
                ____ -> buildJunkBody(____, programClass.getName(), sinkFieldName, desc, paramCount));
            junkMethods.add(new String[] { name, desc });
        }

        if (!junkMethods.isEmpty())
        {
            new InitializerEditor(programClass).addStaticInitializerInstructions(
                /* mergeIntoExistingInitializer */ true,
                ____ -> {
                    for (String[] method : junkMethods)
                    {
                        String desc = method[1];
                        int paramCount = countIntParams(desc);
                        for (int a = 0; a < paramCount; a++)
                        {
                            ____.iconst_0();
                        }
                        ____.invokestatic(programClass.getName(), method[0], desc);
                        if (desc.charAt(desc.length() - 1) == 'I')
                        {
                            // Discard the returned int (void call site).
                            ____.pop();
                        }
                    }
                });
        }
    }

    // ──────────────────────────────────────────────────────────────
    // AttributeVisitor: inline dead-branch injection into existing methods
    // ──────────────────────────────────────────────────────────────

    @Override
    public void visitAnyAttribute(Clazz clazz, Attribute attribute) {}

    @Override
    public void visitCodeAttribute(Clazz clazz, Method method, CodeAttribute codeAttribute)
    {
        if (!(clazz instanceof ProgramClass))
        {
            return;
        }

        // Never touch the class/instance initializers: inserting stack-imbalanced
        // or object-referencing code before super()/field init is fragile.
        String name = method.getName(clazz);
        if (name.equals("<init>") || name.equals("<clinit>"))
        {
            return;
        }

        // Leave pathologically large methods alone: the JVM caps a method's
        // bytecode at 64 KiB, and we never want our junk to be what tips a
        // near-limit method over the edge.
        if (codeAttribute.u4codeLength > 60000)
        {
            return;
        }

        ProgramClass programClass = (ProgramClass)clazz;
        String       owner        = programClass.getName();

        // ── Pick safe mid-method insertion points BEFORE editing ──────────
        // (offsets are computed against the original, un-edited code).
        List<Integer> midOffsets = collectSafeMidOffsets(clazz, method, codeAttribute);

        codeAttributeEditor.reset(codeAttribute.u4codeLength);

        // ── Polymorphic inline dead branches at the method ENTRY ──────────
        // Stack 1..3 opaque-guarded dead branches, each drawing a *different*
        // guard shape and a *different* random combination of dead-block
        // fragments. This turns the junk from a single recognizable pattern
        // (which a de-obfuscator could match & strip in bulk) into heterogeneous
        // noise whose per-site instruction sequence varies, while every guard
        // still reduces to the one rock-solid invariant "jo is even" so
        // behaviour never changes.
        insertDeadBranches(programClass, owner, 0,
                           /* units     */ 1 + rand.nextInt(3),
                           /* fragMax   */ 3);

        // ── Same, but spliced into random MID-METHOD basic-block boundaries ──
        // Injecting only at the entry leaves the *interior* CFG of the method
        // identical to the source; splicing extra opaque-guarded blocks at
        // interior offsets (loop bodies, branch joins, ...) fragments the real
        // method's control-flow graph far more thoroughly, which is exactly the
        // fingerprint structural-similarity detectors key on. These are kept
        // lighter (1..2 units / 1..2 fragments) than the entry so per-method
        // size stays modest.
        for (int off : midOffsets)
        {
            insertDeadBranches(programClass, owner, off,
                               /* units   */ 1 + rand.nextInt(2),
                               /* fragMax */ 2);
        }

        codeAttribute.accept(clazz, method, codeAttributeEditor);
    }

    /**
     * Builds an isolated polymorphic dead-branch sequence and splices it in
     * before the instruction at {@code offset}. Each call uses its own fresh
     * {@link InstructionSequenceBuilder} and its own labels, so multiple
     * insertions can be batched on the shared {@link #codeAttributeEditor}
     * before a single {@code accept}.
     */
    private void insertDeadBranches(ProgramClass programClass,
                                    String       owner,
                                    int          offset,
                                    int          units,
                                    int          fragMax)
    {
        InstructionSequenceBuilder ____ =
            new InstructionSequenceBuilder(programClass);

        for (int u = 0; u < units; u++)
        {
            // SKIP is the join point; the opaque guard always branches here, so
            // the fragments in between are never executed at runtime. The label
            // sits at the end of the sequence, i.e. it resolves to the original
            // instruction that used to live at 'offset'.
            CodeAttributeEditor.Label skip = codeAttributeEditor.label();

            emitOpaqueGuard(____, owner, skip);

            int fragments = 1 + rand.nextInt(fragMax);
            for (int f = 0; f < fragments; f++)
            {
                emitDeadFragment(____, owner);
            }

            ____.label(skip);
        }

        codeAttributeEditor.insertBeforeInstruction(offset, ____.instructions());
    }

    /**
     * Selects a random, size-bounded subset of <em>safe</em> mid-method
     * insertion offsets. An offset is safe iff it is a real instruction start,
     * is reachable, and the operand stack is <em>empty</em> there. Requiring an
     * empty stack automatically rules out the two things that would make an
     * inserted forward branch unverifiable:
     * <ul>
     *   <li>exception-handler entries (the caught exception sits on the stack,
     *       so height == 1), and</li>
     *   <li>the gap between a {@code new} and its {@code <init>} (an
     *       uninitialized reference sits on the stack, so height &gt;= 1).</li>
     * </ul>
     * Because the guard is an opaque predicate that is always taken, the spliced
     * block never executes, so being inside a {@code try} range is harmless too.
     * Any analysis hiccup (e.g. legacy {@code jsr}/{@code ret} subroutines)
     * falls back to entry-only injection.
     */
    private List<Integer> collectSafeMidOffsets(Clazz         clazz,
                                                Method        method,
                                                CodeAttribute codeAttribute)
    {
        List<Integer> chosen = new ArrayList<>();
        try
        {
            // 1) Compute stack heights over the original code.
            codeAttribute.accept(clazz, method, stackSizeComputer);

            // 2) Gather every real instruction offset.
            final List<Integer> allOffsets = new ArrayList<>();
            codeAttribute.instructionsAccept(clazz, method, new InstructionVisitor()
            {
                @Override
                public void visitAnyInstruction(Clazz c, Method m, CodeAttribute ca,
                                                int off, Instruction instruction)
                {
                    allOffsets.add(off);
                }
            });

            // 3) Keep only reachable, empty-stack, non-entry offsets.
            List<Integer> candidates = new ArrayList<>();
            for (int off : allOffsets)
            {
                if (off == 0)                                  continue; // entry handled separately
                if (!stackSizeComputer.isReachable(off))       continue;
                if (stackSizeComputer.getStackSizeBefore(off) != 0) continue;
                candidates.add(off);
            }

            // 4) Budget by method size, then pick a random subset.
            int budget = Math.min(candidates.size(), 1 + codeAttribute.u4codeLength / 250);
            budget     = Math.min(budget, 6);
            for (int i = 0; i < budget && !candidates.isEmpty(); i++)
            {
                chosen.add(candidates.remove(rand.nextInt(candidates.size())));
            }
        }
        catch (Throwable t)
        {
            // Defensive: never let a single awkward method break the build.
            chosen.clear();
        }
        return chosen;
    }

    /**
     * Emits one of several structurally-distinct opaque guards. Every variant
     * evaluates to a condition that is <em>always</em> true at runtime (derived
     * solely from the invariant "{@code jo} is even", which holds even under
     * 32-bit overflow because parity is preserved mod 2), and branches to
     * {@code skip} — so the following dead block is always skipped. Because the
     * optimizer cannot prove {@code jo}'s parity, none of these branches can be
     * folded away.
     *
     * <p>All variants use only {@code ifeq}/{@code ifne} (no {@code if_icmp*})
     * and touch no local variables, so no {@code maxLocals} bump is needed.</p>
     */
    private void emitOpaqueGuard(InstructionSequenceBuilder ____,
                                 String                     owner,
                                 CodeAttributeEditor.Label  skip)
    {
        switch (rand.nextInt(5))
        {
            case 0: // jo % 2 == 0  -> ifeq (taken)
                ____.getstatic(owner, opaqueFieldName, "I")
                    .iconst_2().irem().ifeq(skip.offset());
                break;
            case 1: // jo & 1 == 0  -> ifeq (taken)
                ____.getstatic(owner, opaqueFieldName, "I")
                    .iconst_1().iand().ifeq(skip.offset());
                break;
            case 2: // (jo * jo) & 1 == 0  -> ifeq (taken)
                ____.getstatic(owner, opaqueFieldName, "I")
                    .dup().imul().iconst_1().iand().ifeq(skip.offset());
                break;
            case 3: // (jo & 1) ^ 1 == 1  -> ifne (taken)
                ____.getstatic(owner, opaqueFieldName, "I")
                    .iconst_1().iand().iconst_1().ixor().ifne(skip.offset());
                break;
            default: // (jo % 2) + 1 == 1 (non-zero)  -> ifne (taken)
                ____.getstatic(owner, opaqueFieldName, "I")
                    .iconst_2().irem().iconst_1().iadd().ifne(skip.offset());
                break;
        }
    }

    /**
     * Emits one dead-block fragment from a pool of stack-only, net-stack-zero
     * shapes. Every fragment ends in a non-removable side effect (a volatile
     * field write and/or a {@code Math.random()} / {@code System.nanoTime()}
     * call) so the optimizer's dead-store elimination cannot empty the block.
     * Fragments never use local variables, keeping the insertion {@code maxLocals}-safe.
     */
    private void emitDeadFragment(InstructionSequenceBuilder ____, String owner)
    {
        int k = rand.nextInt(1000) + 1;
        switch (rand.nextInt(8))
        {
            case 0: // jf += k
                ____.getstatic(owner, sinkFieldName, "I")
                    .ldc(k).iadd().putstatic(owner, sinkFieldName, "I");
                break;
            case 1: // jf ^= k
                ____.getstatic(owner, sinkFieldName, "I")
                    .ldc(k).ixor().putstatic(owner, sinkFieldName, "I");
                break;
            case 2: // jf *= jo
                ____.getstatic(owner, sinkFieldName, "I")
                    .getstatic(owner, opaqueFieldName, "I").imul()
                    .putstatic(owner, sinkFieldName, "I");
                break;
            case 3: // Math.random()  (discarded)
                ____.invokestatic("java/lang/Math", "random", "()D").pop2();
                break;
            case 4: // jf += (int) System.nanoTime()
                ____.invokestatic("java/lang/System", "nanoTime", "()J")
                    .l2i().getstatic(owner, sinkFieldName, "I").iadd()
                    .putstatic(owner, sinkFieldName, "I");
                break;
            case 5: // jf = (int) System.currentTimeMillis()
                ____.invokestatic("java/lang/System", "currentTimeMillis", "()J")
                    .l2i().putstatic(owner, sinkFieldName, "I");
                break;
            case 6: // jf += new StringBuilder().append("j"+hex).length()
                ____.new_("java/lang/StringBuilder").dup()
                    .invokespecial("java/lang/StringBuilder", "<init>", "()V")
                    .ldc("j" + Integer.toHexString(k))
                    .invokevirtual("java/lang/StringBuilder", "append",
                                   "(Ljava/lang/String;)Ljava/lang/StringBuilder;")
                    .invokevirtual("java/lang/StringBuilder", "length", "()I")
                    .getstatic(owner, sinkFieldName, "I").iadd()
                    .putstatic(owner, sinkFieldName, "I");
                break;
            default: // jf = Math.abs(jf) | k
                ____.getstatic(owner, sinkFieldName, "I")
                    .invokestatic("java/lang/Math", "abs", "(I)I")
                    .ldc(k).ior().putstatic(owner, sinkFieldName, "I");
                break;
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    /**
     * Builds a meaningless but verifiable method body that nonetheless has an
     * observable side effect (volatile read-modify-write + {@code Math.random()}):
     *
     * <pre>
     *   // t0/t1/t2 are local ints, seeded from the parameters when present
     *   t1 = (a + b) * c;
     *   t2 = (d & e) ^ f;
     *   if (((t1 & 1) != 0)) { t0 = (t0 + t1) * g; } else { t2 = (t2 - t1) + h; }   // opaque #1
     *   StringBuilder sb = new StringBuilder(); sb.append("j" + a); sb.toString(); sb.length();
     *   int[] arr = new int[3]; arr[0] = t1; arr[1] = t2; t0 = arr[0] + arr[1];
     *   if (((t1 & t2) != 0)) { t0 = t0 + k; } else { t2 = t2 * g; }               // opaque #2
     *   jf = jf + k;                                                                 // volatile RMW (observable)
     *   Math.random();                                                               // non-pure call (observable)
     *   return (p0 (+ p1)) ^ t0 ^ t2;   // only for int-returning descriptors
     * </pre>
     */
    private void buildJunkBody(CompactCodeAttributeComposer ____,
                               String ownerClass,
                               String fieldName,
                               String descriptor,
                               int    paramCount)
    {
        int t0 = paramCount;
        int t1 = paramCount + 1;
        int t2 = paramCount + 2;
        int strLocal = paramCount + 3;
        int arrLocal = paramCount + 4;

        int a = rand.nextInt(1000);
        int b = rand.nextInt(1000);
        int c = rand.nextInt(1000);
        int d = rand.nextInt(1000);
        int e = rand.nextInt(1000);
        int f = rand.nextInt(1000);
        int g = rand.nextInt(1000);
        int h = rand.nextInt(1000);
        int k = rand.nextInt(1000);

        // Seed the temporaries with the parameters so they look "used".
        if (paramCount >= 1)
        {
            ____.iload(0).istore(t0);
        }
        if (paramCount >= 2)
        {
            ____.iload(1).ldc(7).iadd().istore(t1);
        }

        ____.iconst_0().istore(t0);                                  // t0 = 0
        ____.ldc(a).ldc(b).iadd().ldc(c).imul().istore(t1);          // t1 = (a + b) * c
        ____.ldc(d).ldc(e).iand().ldc(f).ixor().istore(t2);          // t2 = (d & e) ^ f

        // ── opaque predicate #1 ──
        CompactCodeAttributeComposer.Label dead1 = ____.createLabel();
        CompactCodeAttributeComposer.Label join1 = ____.createLabel();
        ____.iload(t1).iconst_1().iand().ifne(dead1);
        ____.iload(t0).iload(t1).iadd().ldc(g).imul().istore(t0);    // dead (even) branch
        ____.goto_(join1);
        ____.label(dead1);
        ____.iload(t2).iload(t1).isub().ldc(h).iadd().istore(t2);    // dead (odd) branch
        ____.label(join1);

        // ── String concatenation flavor ──
        ____.new_("java/lang/StringBuilder").dup()
            .invokespecial("java/lang/StringBuilder", "<init>", "()V")
            .ldc("j" + Integer.toHexString(a))
            .invokevirtual("java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;")
            .invokevirtual("java/lang/StringBuilder", "toString", "()Ljava/lang/String;")
            .astore(strLocal);
        ____.aload(strLocal).invokevirtual("java/lang/String", "length", "()I").pop();

        // ── int[] flavor ──
        ____.iconst_3().newarray(Instruction.ARRAY_T_INT).astore(arrLocal);
        ____.aload(arrLocal).iconst_0().iload(t1).iastore();
        ____.aload(arrLocal).iconst_1().iload(t2).iastore();
        ____.aload(arrLocal).iconst_0().iaload()
            .aload(arrLocal).iconst_1().iaload().iadd().istore(t0);

        // ── opaque predicate #2 (different shape) ──
        CompactCodeAttributeComposer.Label dead2 = ____.createLabel();
        CompactCodeAttributeComposer.Label join2 = ____.createLabel();
        ____.iload(t1).iload(t2).iand().ifne(dead2);
        ____.iload(t0).ldc(k).iadd().istore(t0);                     // dead branch
        ____.goto_(join2);
        ____.label(dead2);
        ____.iload(t2).ldc(g).imul().istore(t2);                     // dead branch
        ____.label(join2);

        // ── observable side effects (so shrink / optimize keep the method) ──
        ____.getstatic(ownerClass, fieldName, "I")
            .ldc(k).iadd()
            .putstatic(ownerClass, fieldName, "I");                  // volatile RMW
        ____.invokestatic("java/lang/Math", "random", "()D").pop2();// non-pure call

        // ── return ──
        if (descriptor.charAt(descriptor.length() - 1) == 'I')
        {
            if (paramCount >= 2)
            {
                ____.iload(0).iload(1).iadd().iload(t0).ixor().ireturn();
            }
            else
            {
                ____.iload(0).ldc(31).imul().iload(t0).iadd().iload(t2).ixor().ireturn();
            }
        }
        else
        {
            ____.return_();
        }
    }

    /** Number of {@code int} parameters in a descriptor such as {@code (II)V}. */
    private static int countIntParams(String descriptor)
    {
        int count = 0;
        for (int i = 1; descriptor.charAt(i) != ')'; i++)
        {
            if (descriptor.charAt(i) == 'I')
            {
                count++;
            }
        }
        return count;
    }

    /**
     * Generates a unique, valid Java identifier for a synthesized method,
     * avoiding collision with existing members of the class for the same
     * descriptor.
     */
    private String nextMethodName(ProgramClass programClass, String descriptor)
    {
        for (int attempt = 0; attempt < 32; attempt++)
        {
            String name = "j" + Long.toHexString(Math.abs(rand.nextLong())) + "_" + attempt;
            if (programClass.findMethod(name, descriptor) == null)
            {
                return name;
            }
        }
        // Fallback: almost impossible to reach.
        return "j" + System.nanoTime();
    }
}
