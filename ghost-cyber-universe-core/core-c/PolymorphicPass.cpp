#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Constants.h"
#include <random>
#include <algorithm>

using namespace llvm;

namespace {

/**
 * Genjutsu Engine - Polymorphic Pass
 * 
 * LLVM transformation pass that implements polymorphic code generation
 * with advanced obfuscation techniques:
 * - Instruction substitution
 * - Bogus control flow insertion
 * - Constant obfuscation
 * - Dead code insertion
 */
class PolymorphicPass : public ModulePass {
public:
    static char ID;
    std::mt19937 rng;
    
    PolymorphicPass() : ModulePass(ID) {
        std::random_device rd;
        rng.seed(rd());
    }

    bool runOnModule(Module &M) override {
        bool modified = false;
        
        errs() << "[Genjutsu] Starting polymorphic transformation...\n";
        
        for (Function &F : M) {
            if (F.isDeclaration())
                continue;
                
            modified |= obfuscateFunction(F);
        }
        
        errs() << "[Genjutsu] Transformation complete.\n";
        return modified;
    }

private:
    bool obfuscateFunction(Function &F) {
        bool modified = false;
        
        // Apply various obfuscation techniques
        modified |= insertBogusCF(F);
        modified |= substituteInstructions(F);
        modified |= obfuscateConstants(F);
        modified |= insertDeadCode(F);
        
        return modified;
    }
    
    /**
     * Insert bogus control flow to confuse static analysis
     */
    bool insertBogusCF(Function &F) {
        std::vector<BasicBlock*> blocks;
        for (BasicBlock &BB : F) {
            blocks.push_back(&BB);
        }
        
        if (blocks.size() < 2)
            return false;
            
        bool modified = false;
        std::uniform_int_distribution<> dist(0, blocks.size() - 1);
        
        // Insert bogus branches in 30% of blocks
        for (BasicBlock *BB : blocks) {
            if (rng() % 100 < 30) {
                modified |= insertOpaquePredicate(BB, blocks[dist(rng)]);
            }
        }
        
        return modified;
    }
    
    /**
     * Insert an opaque predicate (always true/false but hard to analyze)
     */
    bool insertOpaquePredicate(BasicBlock *BB, BasicBlock *BogusDest) {
        Instruction *FirstInst = &*BB->getFirstInsertionPt();
        IRBuilder<> Builder(FirstInst);
        
        // Create opaque predicate: (x * (x + 1)) % 2 == 0 (always true)
        Value *X = Builder.getInt32(rng() % 100 + 1);
        Value *XPlus1 = Builder.CreateAdd(X, Builder.getInt32(1));
        Value *Mult = Builder.CreateMul(X, XPlus1);
        Value *Mod = Builder.CreateURem(Mult, Builder.getInt32(2));
        Value *Cond = Builder.CreateICmpEQ(Mod, Builder.getInt32(0));
        
        // Split block and insert conditional branch
        BasicBlock *OrigDest = BB->splitBasicBlock(FirstInst, "real_dest");
        BasicBlock *BogusBB = BasicBlock::Create(BB->getContext(), "bogus", BB->getParent());
        
        // Remove unconditional branch created by split
        BB->getTerminator()->eraseFromParent();
        
        // Insert conditional branch (always takes OrigDest path)
        Builder.SetInsertPoint(BB);
        Builder.CreateCondBr(Cond, OrigDest, BogusBB);
        
        // Fill bogus block with junk code
        Builder.SetInsertPoint(BogusBB);
        Value *Junk = Builder.getInt32(0);
        for (int i = 0; i < 5; i++) {
            Junk = Builder.CreateAdd(Junk, Builder.getInt32(rng() % 100));
        }
        Builder.CreateBr(OrigDest);
        
        return true;
    }
    
    /**
     * Substitute simple instructions with more complex equivalents
     */
    bool substituteInstructions(Function &F) {
        std::vector<Instruction*> toReplace;
        
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                if (auto *BinOp = dyn_cast<BinaryOperator>(&I)) {
                    // 50% chance to substitute
                    if (rng() % 100 < 50) {
                        toReplace.push_back(BinOp);
                    }
                }
            }
        }
        
        for (Instruction *I : toReplace) {
            substituteInstruction(I);
        }
        
        return !toReplace.empty();
    }
    
    /**
     * Substitute a single instruction
     */
    void substituteInstruction(Instruction *I) {
        IRBuilder<> Builder(I);
        BinaryOperator *BinOp = dyn_cast<BinaryOperator>(I);
        
        if (!BinOp)
            return;
            
        Value *Op0 = BinOp->getOperand(0);
        Value *Op1 = BinOp->getOperand(1);
        Value *Result = nullptr;
        
        switch (BinOp->getOpcode()) {
            case Instruction::Add:
                // Replace: a + b => (a - (-b))
                Result = Builder.CreateSub(Op0, Builder.CreateNeg(Op1));
                break;
                
            case Instruction::Sub:
                // Replace: a - b => (a + (-b))
                Result = Builder.CreateAdd(Op0, Builder.CreateNeg(Op1));
                break;
                
            case Instruction::Xor:
                // Replace: a ^ b => (a | b) & ~(a & b)
                {
                    Value *Or = Builder.CreateOr(Op0, Op1);
                    Value *And = Builder.CreateAnd(Op0, Op1);
                    Value *NotAnd = Builder.CreateNot(And);
                    Result = Builder.CreateAnd(Or, NotAnd);
                }
                break;
                
            default:
                return; // Don't substitute this instruction
        }
        
        if (Result) {
            I->replaceAllUsesWith(Result);
            I->eraseFromParent();
        }
    }
    
    /**
     * Obfuscate constant values
     */
    bool obfuscateConstants(Function &F) {
        std::vector<Instruction*> toModify;
        
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                for (Use &U : I.operands()) {
                    if (isa<ConstantInt>(U.get())) {
                        toModify.push_back(&I);
                        break;
                    }
                }
            }
        }
        
        for (Instruction *I : toModify) {
            obfuscateConstantsInInstruction(I);
        }
        
        return !toModify.empty();
    }
    
    /**
     * Obfuscate constants in a single instruction
     */
    void obfuscateConstantsInInstruction(Instruction *I) {
        IRBuilder<> Builder(I);
        
        for (unsigned i = 0; i < I->getNumOperands(); i++) {
            if (ConstantInt *CI = dyn_cast<ConstantInt>(I->getOperand(i))) {
                // Replace constant C with: (C + R) - R where R is random
                int64_t C = CI->getSExtValue();
                int64_t R = rng() % 1000 + 1;
                
                Value *CplusR = Builder.getInt(CI->getType()->getBitWidth(), C + R);
                Value *RVal = Builder.getInt(CI->getType()->getBitWidth(), R);
                Value *Result = Builder.CreateSub(CplusR, RVal);
                
                I->setOperand(i, Result);
            }
        }
    }
    
    /**
     * Insert dead code that will never execute
     */
    bool insertDeadCode(Function &F) {
        std::vector<BasicBlock*> blocks;
        for (BasicBlock &BB : F) {
            blocks.push_back(&BB);
        }
        
        if (blocks.empty())
            return false;
            
        // Insert dead code in 20% of blocks
        bool modified = false;
        for (BasicBlock *BB : blocks) {
            if (rng() % 100 < 20) {
                Instruction *InsertPoint = &*BB->getFirstInsertionPt();
                IRBuilder<> Builder(InsertPoint);
                
                // Create unreachable dead code
                Value *Dead = Builder.getInt32(0);
                for (int i = 0; i < 3; i++) {
                    Dead = Builder.CreateAdd(Dead, Builder.getInt32(rng() % 100));
                    Dead = Builder.CreateMul(Dead, Builder.getInt32(rng() % 10 + 1));
                }
                
                modified = true;
            }
        }
        
        return modified;
    }
};

} // anonymous namespace

char PolymorphicPass::ID = 0;
static RegisterPass<PolymorphicPass> X("genjutsu", "Genjutsu Polymorphic Transformation Pass",
                                       false /* Only looks at CFG */,
                                       false /* Analysis Pass */);
