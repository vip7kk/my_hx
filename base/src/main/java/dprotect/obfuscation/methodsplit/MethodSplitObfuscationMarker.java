package dprotect.obfuscation.methodsplit;

import dprotect.ObfuscationClassSpecification;

import dprotect.obfuscation.info.ObfuscationInfo;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import proguard.classfile.*;
import proguard.classfile.visitor.ClassVisitor;
import proguard.classfile.visitor.*;

/**
 * Marks program classes selected by {@code -obfuscate-method-split} so that the
 * {@link MethodSplitObfuscation} pass knows which classes must have their
 * eligible methods split into a rename-based trampoline (a same-named/same-signature
 * forwarding stub in front of the real, renamed method body).
 */
public class MethodSplitObfuscationMarker
implements   ClassVisitor,
             MemberVisitor
{
    private static final Logger logger = LogManager.getLogger(MethodSplitObfuscationMarker.class);

    @SuppressWarnings("unused")
    private final ObfuscationClassSpecification spec;

    public MethodSplitObfuscationMarker(ObfuscationClassSpecification spec)
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
        info.methodSplit = true;
    }

    // Implementations for MemberVisitor.

    @Override
    public void visitAnyMember(Clazz clazz, Member member) { }

    @Override
    public void visitProgramMethod(ProgramClass programClass, ProgramMethod programMethod) { }

    @Override
    public void visitProgramField(ProgramClass programClass, ProgramField programField) { }
}
