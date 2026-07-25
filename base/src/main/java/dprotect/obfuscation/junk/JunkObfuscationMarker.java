package dprotect.obfuscation.junk;

import dprotect.ObfuscationClassSpecification;

import dprotect.obfuscation.info.ObfuscationInfo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import proguard.classfile.*;
import proguard.classfile.visitor.ClassVisitor;
import proguard.classfile.visitor.*;

/**
 * Marks program classes selected by {@code -obfuscate-junk} so that the
 * {@link JunkCodeObfuscation} pass knows where to inject junk methods.
 */
public class JunkObfuscationMarker
implements   ClassVisitor,
             MemberVisitor
{
    private static final Logger logger = LogManager.getLogger(JunkObfuscationMarker.class);

    @SuppressWarnings("unused")
    private final ObfuscationClassSpecification spec;

    public JunkObfuscationMarker(ObfuscationClassSpecification spec)
    {
        this.spec = spec;
    }

    // Implementations for ClassVisitor.

    @Override
    public void visitAnyClass(Clazz clazz) { }

    @Override
    public void visitProgramClass(ProgramClass programClass)
    {
        ObfuscationInfo info = ObfuscationInfo.getObfuscationInfo(programClass);
        info.junk = true;
        // Carry the per-target junk-method count so CodeObfuscator can inject
        // the exact number requested for this class group.
        if (spec.count > 0)
        {
            info.junkCount = spec.count;
        }
    }

    // Implementations for MemberVisitor.

    @Override
    public void visitAnyMember(Clazz clazz, Member member) { }

    @Override
    public void visitProgramMethod(ProgramClass programClass, ProgramMethod programMethod) { }

    @Override
    public void visitProgramField(ProgramClass programClass, ProgramField programField) { }
}
