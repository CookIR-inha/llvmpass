// UAFDetector.cpp

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

//main함수에 allocate_shadow_memory 함수 삽입하기 위한 Pass
struct InsertShadowMemoryAllocation : public PassInfoMixin<InsertShadowMemoryAllocation> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        
        LLVMContext &Context = M.getContext();

        //--------------------------------------------------------------------------------------------------
        // main함수에 allocate_shadow_memory 함수 호출 삽입

        // allocate_shadow_memory 함수 시그니처
        FunctionCallee allocate_shadow_memory = M.getOrInsertFunction(
            "allocate_shadow_memory",
            FunctionType::get(Type::getVoidTy(Context), false)
        );

        // main 함수 찾기
        Function *mainFunc = M.getFunction("main");
        if (!mainFunc) {
            errs() << "main 함수가 모듈에 존재하지 않습니다.\n";
            return PreservedAnalyses::all();
        }

        // main 함수가 선언만 되어 있는지 확인
        if (mainFunc->isDeclaration()) {
            errs() << "main 함수가 정의되어 있지 않습니다.\n";
            return PreservedAnalyses::all();
        }

        // main 함수의 첫 번째 블록 찾기
        BasicBlock &entryBlock = mainFunc->getEntryBlock();

        // 첫 번째 명령어 앞에 삽입하기 위한 IRBuilder 설정
        IRBuilder<> builder(&*entryBlock.getFirstInsertionPt());

        // allocate_shadow_memory() 호출 생성
        builder.CreateCall(allocate_shadow_memory);


        //--------------------------------------------------------------------------------------------------
        // malloc, aligned_alloc, @_Znwm (new), @_Znam (new[]) 이후에 after_malloc 호출 삽입

        // after_malloc 함수 시그니처
        FunctionCallee after_malloc = M.getOrInsertFunction(
            "after_malloc",
            FunctionType::get(Type::getVoidTy(Context),
                              {Type::getInt8PtrTy(Context), Type::getInt64Ty(Context)},
                              false)
        );

        std::vector<std::string> allocFuncNames = {
            "malloc",
            "aligned_alloc",
            "_Znwm", // operator new
            "_Znam"  // operator new[]
        };

        for (Function &F : M) {

            // 함수가 선언만 되어있는 경우 스킵(정의가 아닌)
            if (F.isDeclaration()) continue;

            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    // CallInst인지 확인
                    if (auto *call = dyn_cast<CallInst>(&I)) {
                        Function *calledFunc = call->getCalledFunction();

                        //간접호출인 경우 무시(함수포인터 등)
                        if (!calledFunc) continue;

                        std::string funcName = calledFunc->getName().str();

                        // 감지된 함수 이름인지 확인
                        if (std::find(allocFuncNames.begin(), allocFuncNames.end(), funcName) != allocFuncNames.end()) {

                            // 할당된 주소 (malloc류 함수의 리턴값)
                            Value *addr = call;

                            // 할당 크기
                            Value *size = nullptr;

                            if (funcName == "malloc" || funcName == "_Znwm" || funcName == "_Znam") {
                                size = call->getArgOperand(0);
                            } else if (funcName == "aligned_alloc") {
                                size = call->getArgOperand(1);
                            }

                            // after_malloc(addr, size) 호출 생성
                            IRBuilder<> afterBuilder(call->getNextNode());
                            afterBuilder.CreateCall(after_malloc, {addr, size});
                        }
                    } //InvokeInst인지 확인
                    else if (auto *invoke = dyn_cast<InvokeInst>(&I)) {
                        Function *calledFunc = invoke->getCalledFunction();
                        if (!calledFunc) continue;

                        std::string funcName = calledFunc->getName().str();

                        if (std::find(allocFuncNames.begin(), allocFuncNames.end(), funcName) != allocFuncNames.end()) {

                            // 할당된 주소 (malloc류 함수의 리턴값)
                            Value *addr = invoke;

                            // 할당 크기
                            Value *size = nullptr;

                            if (funcName == "malloc" || funcName == "_Znwm" || funcName == "_Znam") {
                                size = invoke->getArgOperand(0);
                            } else if (funcName == "aligned_alloc") {
                                size = invoke->getArgOperand(1);
                            }

                            // after_malloc(addr, size) 호출 생성
                            BasicBlock *normalDest = invoke->getNormalDest();
                            IRBuilder<> afterBuilder(&*normalDest->getFirstInsertionPt());
                            afterBuilder.CreateCall(after_malloc, {addr, size});
                        }                        
                    }
                }
            }
        }

        return PreservedAnalyses::none();
    }
};


} //namespace


extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
	return {
		LLVM_PLUGIN_API_VERSION,
		"UAFDetector",
		LLVM_VERSION_STRING,
		[](PassBuilder &PB) {
			PB.registerPipelineParsingCallback(
				[](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
					if (Name == "UAFDetector") {
						MPM.addPass(InsertShadowMemoryAllocation());
						return true;
					}
					return false;
				}
			);
		}
	};
}