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

        // allocate_shadow_memory 함수 선언 가져오기
        FunctionCallee allocate_shadow_memory = M.getOrInsertFunction(
            "allocate_shadow_memory",
            FunctionType::get(Type::getVoidTy(M.getContext()), false)
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