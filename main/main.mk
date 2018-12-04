##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=main
ConfigurationName      :=Debug
WorkspacePath          :=/home/thomas/Prog/holodec
ProjectPath            :=/home/thomas/Prog/holodec/main
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=thomas
Date                   :=09/10/18
CodeLitePath           :=/home/thomas/.codelite
LinkerName             :=/usr/bin/g++
SharedObjectLinkerName :=/usr/bin/g++ -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
Preprocessors          :=$(PreprocessorSwitch)HOLODEC_REMOVE_OBVIOUS 
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :="main.txt"
PCHCompileFlags        :=
MakeDirCommand         :=mkdir -p
LinkOptions            :=  
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). $(IncludeSwitch)../capstone/include 
IncludePCH             := 
RcIncludePath          := 
Libs                   := $(LibrarySwitch)capstone 
ArLibs                 :=  "capstone" 
LibPath                := $(LibraryPathSwitch). $(LibraryPathSwitch)../capstone/build 

##
## Common variables
## AR, CXX, CC, AS, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := /usr/bin/ar rcu
CXX      := /usr/bin/g++
CC       := /usr/bin/gcc
CXXFLAGS := -std=c++17 -g -O0 $(Preprocessors)
CFLAGS   := -std=c99 -g -O0 $(Preprocessors)
ASFLAGS  := 
AS       := /usr/bin/as


##
## User defined environment variables
##
CodeLiteDir:=/usr/share/codelite
Objects0=$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(ObjectSuffix) $(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(ObjectSuffix) $(IntermediateDirectory)/arch_AvrArchitecture.cpp$(ObjectSuffix) $(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSADCETransformer.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSATransformToC.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSA.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSAGen.cpp$(ObjectSuffix) $(IntermediateDirectory)/InstrDefinition.cpp$(ObjectSuffix) $(IntermediateDirectory)/Binary.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/CallingConvention.cpp$(ObjectSuffix) $(IntermediateDirectory)/Class.cpp$(ObjectSuffix) $(IntermediateDirectory)/PeepholeOptimizer.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/Memory.cpp$(ObjectSuffix) $(IntermediateDirectory)/Stack.cpp$(ObjectSuffix) $(IntermediateDirectory)/main_file.cpp$(ObjectSuffix) $(IntermediateDirectory)/Function.cpp$(ObjectSuffix) $(IntermediateDirectory)/Data.cpp$(ObjectSuffix) $(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/DynamicLibrary.cpp$(ObjectSuffix) $(IntermediateDirectory)/CHolodecStruct.cpp$(ObjectSuffix) $(IntermediateDirectory)/HoloIO.cpp$(ObjectSuffix) $(IntermediateDirectory)/CRepresentation.cpp$(ObjectSuffix) $(IntermediateDirectory)/IR.cpp$(ObjectSuffix) $(IntermediateDirectory)/Register.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSATransformer.cpp$(ObjectSuffix) $(IntermediateDirectory)/ScriptingInterface.cpp$(ObjectSuffix) $(IntermediateDirectory)/Argument.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSAAppendSimplifier.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/General.cpp$(ObjectSuffix) $(IntermediateDirectory)/Section.cpp$(ObjectSuffix) $(IntermediateDirectory)/Main.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(ObjectSuffix) $(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/FileFormat.cpp$(ObjectSuffix) $(IntermediateDirectory)/CHolodec.cpp$(ObjectSuffix) $(IntermediateDirectory)/BinaryAnalyzer.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/FunctionAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/Architecture.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSARedundancyElimination.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(ObjectSuffix) $(IntermediateDirectory)/SSACallingConvApplier.cpp$(ObjectSuffix) $(IntermediateDirectory)/IRGen.cpp$(ObjectSuffix) 



Objects=$(Objects0) 

##
## Main Build Targets 
##
.PHONY: all clean PreBuild PrePreBuild PostBuild MakeIntermediateDirs
all: $(OutputFile)

$(OutputFile): $(IntermediateDirectory)/.d $(Objects) 
	@$(MakeDirCommand) $(@D)
	@echo "" > $(IntermediateDirectory)/.d
	@echo $(Objects0)  > $(ObjectsFileList)
	$(LinkerName) $(OutputSwitch)$(OutputFile) @$(ObjectsFileList) $(LibPath) $(Libs) $(LinkOptions)

MakeIntermediateDirs:
	@test -d ./Debug || $(MakeDirCommand) ./Debug


$(IntermediateDirectory)/.d:
	@test -d ./Debug || $(MakeDirCommand) ./Debug

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(ObjectSuffix): arch/x86/X86Architecture.cpp $(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/arch/x86/X86Architecture.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(DependSuffix): arch/x86/X86Architecture.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(DependSuffix) -MM arch/x86/X86Architecture.cpp

$(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(PreprocessSuffix): arch/x86/X86Architecture.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/arch_x86_X86Architecture.cpp$(PreprocessSuffix) arch/x86/X86Architecture.cpp

$(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(ObjectSuffix): binary/elf/ElfDataFile.cpp $(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/binary/elf/ElfDataFile.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(DependSuffix): binary/elf/ElfDataFile.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(DependSuffix) -MM binary/elf/ElfDataFile.cpp

$(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(PreprocessSuffix): binary/elf/ElfDataFile.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/binary_elf_ElfDataFile.cpp$(PreprocessSuffix) binary/elf/ElfDataFile.cpp

$(IntermediateDirectory)/arch_AvrArchitecture.cpp$(ObjectSuffix): arch/AvrArchitecture.cpp $(IntermediateDirectory)/arch_AvrArchitecture.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/arch/AvrArchitecture.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/arch_AvrArchitecture.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/arch_AvrArchitecture.cpp$(DependSuffix): arch/AvrArchitecture.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/arch_AvrArchitecture.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/arch_AvrArchitecture.cpp$(DependSuffix) -MM arch/AvrArchitecture.cpp

$(IntermediateDirectory)/arch_AvrArchitecture.cpp$(PreprocessSuffix): arch/AvrArchitecture.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/arch_AvrArchitecture.cpp$(PreprocessSuffix) arch/AvrArchitecture.cpp

$(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(ObjectSuffix): arch/AvrFunctionAnalyzer.cpp $(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/arch/AvrFunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(DependSuffix): arch/AvrFunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(DependSuffix) -MM arch/AvrFunctionAnalyzer.cpp

$(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(PreprocessSuffix): arch/AvrFunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/arch_AvrFunctionAnalyzer.cpp$(PreprocessSuffix) arch/AvrFunctionAnalyzer.cpp

$(IntermediateDirectory)/SSADCETransformer.cpp$(ObjectSuffix): SSADCETransformer.cpp $(IntermediateDirectory)/SSADCETransformer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSADCETransformer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSADCETransformer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSADCETransformer.cpp$(DependSuffix): SSADCETransformer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSADCETransformer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSADCETransformer.cpp$(DependSuffix) -MM SSADCETransformer.cpp

$(IntermediateDirectory)/SSADCETransformer.cpp$(PreprocessSuffix): SSADCETransformer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSADCETransformer.cpp$(PreprocessSuffix) SSADCETransformer.cpp

$(IntermediateDirectory)/SSATransformToC.cpp$(ObjectSuffix): SSATransformToC.cpp $(IntermediateDirectory)/SSATransformToC.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSATransformToC.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSATransformToC.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSATransformToC.cpp$(DependSuffix): SSATransformToC.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSATransformToC.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSATransformToC.cpp$(DependSuffix) -MM SSATransformToC.cpp

$(IntermediateDirectory)/SSATransformToC.cpp$(PreprocessSuffix): SSATransformToC.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSATransformToC.cpp$(PreprocessSuffix) SSATransformToC.cpp

$(IntermediateDirectory)/SSA.cpp$(ObjectSuffix): SSA.cpp $(IntermediateDirectory)/SSA.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSA.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSA.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSA.cpp$(DependSuffix): SSA.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSA.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSA.cpp$(DependSuffix) -MM SSA.cpp

$(IntermediateDirectory)/SSA.cpp$(PreprocessSuffix): SSA.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSA.cpp$(PreprocessSuffix) SSA.cpp

$(IntermediateDirectory)/SSAGen.cpp$(ObjectSuffix): SSAGen.cpp $(IntermediateDirectory)/SSAGen.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSAGen.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSAGen.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSAGen.cpp$(DependSuffix): SSAGen.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSAGen.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSAGen.cpp$(DependSuffix) -MM SSAGen.cpp

$(IntermediateDirectory)/SSAGen.cpp$(PreprocessSuffix): SSAGen.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSAGen.cpp$(PreprocessSuffix) SSAGen.cpp

$(IntermediateDirectory)/InstrDefinition.cpp$(ObjectSuffix): InstrDefinition.cpp $(IntermediateDirectory)/InstrDefinition.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/InstrDefinition.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/InstrDefinition.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/InstrDefinition.cpp$(DependSuffix): InstrDefinition.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/InstrDefinition.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/InstrDefinition.cpp$(DependSuffix) -MM InstrDefinition.cpp

$(IntermediateDirectory)/InstrDefinition.cpp$(PreprocessSuffix): InstrDefinition.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/InstrDefinition.cpp$(PreprocessSuffix) InstrDefinition.cpp

$(IntermediateDirectory)/Binary.cpp$(ObjectSuffix): Binary.cpp $(IntermediateDirectory)/Binary.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Binary.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Binary.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Binary.cpp$(DependSuffix): Binary.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Binary.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Binary.cpp$(DependSuffix) -MM Binary.cpp

$(IntermediateDirectory)/Binary.cpp$(PreprocessSuffix): Binary.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Binary.cpp$(PreprocessSuffix) Binary.cpp

$(IntermediateDirectory)/CallingConvention.cpp$(ObjectSuffix): CallingConvention.cpp $(IntermediateDirectory)/CallingConvention.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/CallingConvention.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/CallingConvention.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/CallingConvention.cpp$(DependSuffix): CallingConvention.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/CallingConvention.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/CallingConvention.cpp$(DependSuffix) -MM CallingConvention.cpp

$(IntermediateDirectory)/CallingConvention.cpp$(PreprocessSuffix): CallingConvention.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/CallingConvention.cpp$(PreprocessSuffix) CallingConvention.cpp

$(IntermediateDirectory)/Class.cpp$(ObjectSuffix): Class.cpp $(IntermediateDirectory)/Class.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Class.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Class.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Class.cpp$(DependSuffix): Class.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Class.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Class.cpp$(DependSuffix) -MM Class.cpp

$(IntermediateDirectory)/Class.cpp$(PreprocessSuffix): Class.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Class.cpp$(PreprocessSuffix) Class.cpp

$(IntermediateDirectory)/PeepholeOptimizer.cpp$(ObjectSuffix): PeepholeOptimizer.cpp $(IntermediateDirectory)/PeepholeOptimizer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/PeepholeOptimizer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/PeepholeOptimizer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/PeepholeOptimizer.cpp$(DependSuffix): PeepholeOptimizer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/PeepholeOptimizer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/PeepholeOptimizer.cpp$(DependSuffix) -MM PeepholeOptimizer.cpp

$(IntermediateDirectory)/PeepholeOptimizer.cpp$(PreprocessSuffix): PeepholeOptimizer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/PeepholeOptimizer.cpp$(PreprocessSuffix) PeepholeOptimizer.cpp

$(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(ObjectSuffix): SSAReverseRegUsageAnalyzer.cpp $(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSAReverseRegUsageAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(DependSuffix): SSAReverseRegUsageAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(DependSuffix) -MM SSAReverseRegUsageAnalyzer.cpp

$(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(PreprocessSuffix): SSAReverseRegUsageAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSAReverseRegUsageAnalyzer.cpp$(PreprocessSuffix) SSAReverseRegUsageAnalyzer.cpp

$(IntermediateDirectory)/Memory.cpp$(ObjectSuffix): Memory.cpp $(IntermediateDirectory)/Memory.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Memory.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Memory.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Memory.cpp$(DependSuffix): Memory.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Memory.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Memory.cpp$(DependSuffix) -MM Memory.cpp

$(IntermediateDirectory)/Memory.cpp$(PreprocessSuffix): Memory.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Memory.cpp$(PreprocessSuffix) Memory.cpp

$(IntermediateDirectory)/Stack.cpp$(ObjectSuffix): Stack.cpp $(IntermediateDirectory)/Stack.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Stack.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Stack.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Stack.cpp$(DependSuffix): Stack.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Stack.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Stack.cpp$(DependSuffix) -MM Stack.cpp

$(IntermediateDirectory)/Stack.cpp$(PreprocessSuffix): Stack.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Stack.cpp$(PreprocessSuffix) Stack.cpp

$(IntermediateDirectory)/main_file.cpp$(ObjectSuffix): main_file.cpp $(IntermediateDirectory)/main_file.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/main_file.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/main_file.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/main_file.cpp$(DependSuffix): main_file.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/main_file.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/main_file.cpp$(DependSuffix) -MM main_file.cpp

$(IntermediateDirectory)/main_file.cpp$(PreprocessSuffix): main_file.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/main_file.cpp$(PreprocessSuffix) main_file.cpp

$(IntermediateDirectory)/Function.cpp$(ObjectSuffix): Function.cpp $(IntermediateDirectory)/Function.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Function.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Function.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Function.cpp$(DependSuffix): Function.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Function.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Function.cpp$(DependSuffix) -MM Function.cpp

$(IntermediateDirectory)/Function.cpp$(PreprocessSuffix): Function.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Function.cpp$(PreprocessSuffix) Function.cpp

$(IntermediateDirectory)/Data.cpp$(ObjectSuffix): Data.cpp $(IntermediateDirectory)/Data.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Data.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Data.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Data.cpp$(DependSuffix): Data.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Data.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Data.cpp$(DependSuffix) -MM Data.cpp

$(IntermediateDirectory)/Data.cpp$(PreprocessSuffix): Data.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Data.cpp$(PreprocessSuffix) Data.cpp

$(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix): HStringDatabase.cpp $(IntermediateDirectory)/HStringDatabase.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HStringDatabase.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HStringDatabase.cpp$(DependSuffix): HStringDatabase.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HStringDatabase.cpp$(DependSuffix) -MM HStringDatabase.cpp

$(IntermediateDirectory)/HStringDatabase.cpp$(PreprocessSuffix): HStringDatabase.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HStringDatabase.cpp$(PreprocessSuffix) HStringDatabase.cpp

$(IntermediateDirectory)/DynamicLibrary.cpp$(ObjectSuffix): DynamicLibrary.cpp $(IntermediateDirectory)/DynamicLibrary.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/DynamicLibrary.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/DynamicLibrary.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/DynamicLibrary.cpp$(DependSuffix): DynamicLibrary.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/DynamicLibrary.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/DynamicLibrary.cpp$(DependSuffix) -MM DynamicLibrary.cpp

$(IntermediateDirectory)/DynamicLibrary.cpp$(PreprocessSuffix): DynamicLibrary.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/DynamicLibrary.cpp$(PreprocessSuffix) DynamicLibrary.cpp

$(IntermediateDirectory)/CHolodecStruct.cpp$(ObjectSuffix): CHolodecStruct.cpp $(IntermediateDirectory)/CHolodecStruct.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/CHolodecStruct.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/CHolodecStruct.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/CHolodecStruct.cpp$(DependSuffix): CHolodecStruct.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/CHolodecStruct.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/CHolodecStruct.cpp$(DependSuffix) -MM CHolodecStruct.cpp

$(IntermediateDirectory)/CHolodecStruct.cpp$(PreprocessSuffix): CHolodecStruct.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/CHolodecStruct.cpp$(PreprocessSuffix) CHolodecStruct.cpp

$(IntermediateDirectory)/HoloIO.cpp$(ObjectSuffix): HoloIO.cpp $(IntermediateDirectory)/HoloIO.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HoloIO.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HoloIO.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HoloIO.cpp$(DependSuffix): HoloIO.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HoloIO.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HoloIO.cpp$(DependSuffix) -MM HoloIO.cpp

$(IntermediateDirectory)/HoloIO.cpp$(PreprocessSuffix): HoloIO.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HoloIO.cpp$(PreprocessSuffix) HoloIO.cpp

$(IntermediateDirectory)/CRepresentation.cpp$(ObjectSuffix): CRepresentation.cpp $(IntermediateDirectory)/CRepresentation.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/CRepresentation.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/CRepresentation.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/CRepresentation.cpp$(DependSuffix): CRepresentation.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/CRepresentation.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/CRepresentation.cpp$(DependSuffix) -MM CRepresentation.cpp

$(IntermediateDirectory)/CRepresentation.cpp$(PreprocessSuffix): CRepresentation.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/CRepresentation.cpp$(PreprocessSuffix) CRepresentation.cpp

$(IntermediateDirectory)/IR.cpp$(ObjectSuffix): IR.cpp $(IntermediateDirectory)/IR.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/IR.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/IR.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/IR.cpp$(DependSuffix): IR.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/IR.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/IR.cpp$(DependSuffix) -MM IR.cpp

$(IntermediateDirectory)/IR.cpp$(PreprocessSuffix): IR.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/IR.cpp$(PreprocessSuffix) IR.cpp

$(IntermediateDirectory)/Register.cpp$(ObjectSuffix): Register.cpp $(IntermediateDirectory)/Register.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Register.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Register.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Register.cpp$(DependSuffix): Register.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Register.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Register.cpp$(DependSuffix) -MM Register.cpp

$(IntermediateDirectory)/Register.cpp$(PreprocessSuffix): Register.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Register.cpp$(PreprocessSuffix) Register.cpp

$(IntermediateDirectory)/SSATransformer.cpp$(ObjectSuffix): SSATransformer.cpp $(IntermediateDirectory)/SSATransformer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSATransformer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSATransformer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSATransformer.cpp$(DependSuffix): SSATransformer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSATransformer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSATransformer.cpp$(DependSuffix) -MM SSATransformer.cpp

$(IntermediateDirectory)/SSATransformer.cpp$(PreprocessSuffix): SSATransformer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSATransformer.cpp$(PreprocessSuffix) SSATransformer.cpp

$(IntermediateDirectory)/ScriptingInterface.cpp$(ObjectSuffix): ScriptingInterface.cpp $(IntermediateDirectory)/ScriptingInterface.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/ScriptingInterface.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/ScriptingInterface.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/ScriptingInterface.cpp$(DependSuffix): ScriptingInterface.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/ScriptingInterface.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/ScriptingInterface.cpp$(DependSuffix) -MM ScriptingInterface.cpp

$(IntermediateDirectory)/ScriptingInterface.cpp$(PreprocessSuffix): ScriptingInterface.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/ScriptingInterface.cpp$(PreprocessSuffix) ScriptingInterface.cpp

$(IntermediateDirectory)/Argument.cpp$(ObjectSuffix): Argument.cpp $(IntermediateDirectory)/Argument.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Argument.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Argument.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Argument.cpp$(DependSuffix): Argument.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Argument.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Argument.cpp$(DependSuffix) -MM Argument.cpp

$(IntermediateDirectory)/Argument.cpp$(PreprocessSuffix): Argument.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Argument.cpp$(PreprocessSuffix) Argument.cpp

$(IntermediateDirectory)/SSAAppendSimplifier.cpp$(ObjectSuffix): SSAAppendSimplifier.cpp $(IntermediateDirectory)/SSAAppendSimplifier.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSAAppendSimplifier.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSAAppendSimplifier.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSAAppendSimplifier.cpp$(DependSuffix): SSAAppendSimplifier.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSAAppendSimplifier.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSAAppendSimplifier.cpp$(DependSuffix) -MM SSAAppendSimplifier.cpp

$(IntermediateDirectory)/SSAAppendSimplifier.cpp$(PreprocessSuffix): SSAAppendSimplifier.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSAAppendSimplifier.cpp$(PreprocessSuffix) SSAAppendSimplifier.cpp

$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(ObjectSuffix): binary/elf/ElfBinaryAnalyzer.cpp $(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/binary/elf/ElfBinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(DependSuffix): binary/elf/ElfBinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(DependSuffix) -MM binary/elf/ElfBinaryAnalyzer.cpp

$(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(PreprocessSuffix): binary/elf/ElfBinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/binary_elf_ElfBinaryAnalyzer.cpp$(PreprocessSuffix) binary/elf/ElfBinaryAnalyzer.cpp

$(IntermediateDirectory)/General.cpp$(ObjectSuffix): General.cpp $(IntermediateDirectory)/General.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/General.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/General.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/General.cpp$(DependSuffix): General.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/General.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/General.cpp$(DependSuffix) -MM General.cpp

$(IntermediateDirectory)/General.cpp$(PreprocessSuffix): General.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/General.cpp$(PreprocessSuffix) General.cpp

$(IntermediateDirectory)/Section.cpp$(ObjectSuffix): Section.cpp $(IntermediateDirectory)/Section.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Section.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Section.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Section.cpp$(DependSuffix): Section.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Section.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Section.cpp$(DependSuffix) -MM Section.cpp

$(IntermediateDirectory)/Section.cpp$(PreprocessSuffix): Section.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Section.cpp$(PreprocessSuffix) Section.cpp

$(IntermediateDirectory)/Main.cpp$(ObjectSuffix): Main.cpp $(IntermediateDirectory)/Main.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Main.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Main.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Main.cpp$(DependSuffix): Main.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Main.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Main.cpp$(DependSuffix) -MM Main.cpp

$(IntermediateDirectory)/Main.cpp$(PreprocessSuffix): Main.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Main.cpp$(PreprocessSuffix) Main.cpp

$(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(ObjectSuffix): SSAPhiNodeGenerator.cpp $(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSAPhiNodeGenerator.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(DependSuffix): SSAPhiNodeGenerator.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(DependSuffix) -MM SSAPhiNodeGenerator.cpp

$(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(PreprocessSuffix): SSAPhiNodeGenerator.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSAPhiNodeGenerator.cpp$(PreprocessSuffix) SSAPhiNodeGenerator.cpp

$(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(ObjectSuffix): arch/x86/X86FunctionAnalyzer.cpp $(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/arch/x86/X86FunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(DependSuffix): arch/x86/X86FunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(DependSuffix) -MM arch/x86/X86FunctionAnalyzer.cpp

$(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(PreprocessSuffix): arch/x86/X86FunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/arch_x86_X86FunctionAnalyzer.cpp$(PreprocessSuffix) arch/x86/X86FunctionAnalyzer.cpp

$(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(ObjectSuffix): binary/ihex/IHexBinaryAnalyzer.cpp $(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/binary/ihex/IHexBinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(DependSuffix): binary/ihex/IHexBinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(DependSuffix) -MM binary/ihex/IHexBinaryAnalyzer.cpp

$(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(PreprocessSuffix): binary/ihex/IHexBinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/binary_ihex_IHexBinaryAnalyzer.cpp$(PreprocessSuffix) binary/ihex/IHexBinaryAnalyzer.cpp

$(IntermediateDirectory)/FileFormat.cpp$(ObjectSuffix): FileFormat.cpp $(IntermediateDirectory)/FileFormat.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/FileFormat.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/FileFormat.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/FileFormat.cpp$(DependSuffix): FileFormat.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/FileFormat.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/FileFormat.cpp$(DependSuffix) -MM FileFormat.cpp

$(IntermediateDirectory)/FileFormat.cpp$(PreprocessSuffix): FileFormat.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/FileFormat.cpp$(PreprocessSuffix) FileFormat.cpp

$(IntermediateDirectory)/CHolodec.cpp$(ObjectSuffix): CHolodec.cpp $(IntermediateDirectory)/CHolodec.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/CHolodec.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/CHolodec.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/CHolodec.cpp$(DependSuffix): CHolodec.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/CHolodec.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/CHolodec.cpp$(DependSuffix) -MM CHolodec.cpp

$(IntermediateDirectory)/CHolodec.cpp$(PreprocessSuffix): CHolodec.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/CHolodec.cpp$(PreprocessSuffix) CHolodec.cpp

$(IntermediateDirectory)/BinaryAnalyzer.cpp$(ObjectSuffix): BinaryAnalyzer.cpp $(IntermediateDirectory)/BinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/BinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/BinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/BinaryAnalyzer.cpp$(DependSuffix): BinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/BinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/BinaryAnalyzer.cpp$(DependSuffix) -MM BinaryAnalyzer.cpp

$(IntermediateDirectory)/BinaryAnalyzer.cpp$(PreprocessSuffix): BinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/BinaryAnalyzer.cpp$(PreprocessSuffix) BinaryAnalyzer.cpp

$(IntermediateDirectory)/FunctionAnalyzer.cpp$(ObjectSuffix): FunctionAnalyzer.cpp $(IntermediateDirectory)/FunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/FunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/FunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/FunctionAnalyzer.cpp$(DependSuffix): FunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/FunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/FunctionAnalyzer.cpp$(DependSuffix) -MM FunctionAnalyzer.cpp

$(IntermediateDirectory)/FunctionAnalyzer.cpp$(PreprocessSuffix): FunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/FunctionAnalyzer.cpp$(PreprocessSuffix) FunctionAnalyzer.cpp

$(IntermediateDirectory)/Architecture.cpp$(ObjectSuffix): Architecture.cpp $(IntermediateDirectory)/Architecture.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Architecture.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Architecture.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Architecture.cpp$(DependSuffix): Architecture.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Architecture.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Architecture.cpp$(DependSuffix) -MM Architecture.cpp

$(IntermediateDirectory)/Architecture.cpp$(PreprocessSuffix): Architecture.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Architecture.cpp$(PreprocessSuffix) Architecture.cpp

$(IntermediateDirectory)/SSARedundancyElimination.cpp$(ObjectSuffix): SSARedundancyElimination.cpp $(IntermediateDirectory)/SSARedundancyElimination.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSARedundancyElimination.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSARedundancyElimination.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSARedundancyElimination.cpp$(DependSuffix): SSARedundancyElimination.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSARedundancyElimination.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSARedundancyElimination.cpp$(DependSuffix) -MM SSARedundancyElimination.cpp

$(IntermediateDirectory)/SSARedundancyElimination.cpp$(PreprocessSuffix): SSARedundancyElimination.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSARedundancyElimination.cpp$(PreprocessSuffix) SSARedundancyElimination.cpp

$(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(ObjectSuffix): SSAAddressToBlockTransformer.cpp $(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSAAddressToBlockTransformer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(DependSuffix): SSAAddressToBlockTransformer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(DependSuffix) -MM SSAAddressToBlockTransformer.cpp

$(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(PreprocessSuffix): SSAAddressToBlockTransformer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSAAddressToBlockTransformer.cpp$(PreprocessSuffix) SSAAddressToBlockTransformer.cpp

$(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(ObjectSuffix): SSACalleeCallerRegs.cpp $(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSACalleeCallerRegs.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(DependSuffix): SSACalleeCallerRegs.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(DependSuffix) -MM SSACalleeCallerRegs.cpp

$(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(PreprocessSuffix): SSACalleeCallerRegs.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSACalleeCallerRegs.cpp$(PreprocessSuffix) SSACalleeCallerRegs.cpp

$(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(ObjectSuffix): SSAPeepholeOptimizer.cpp $(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSAPeepholeOptimizer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(DependSuffix): SSAPeepholeOptimizer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(DependSuffix) -MM SSAPeepholeOptimizer.cpp

$(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(PreprocessSuffix): SSAPeepholeOptimizer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSAPeepholeOptimizer.cpp$(PreprocessSuffix) SSAPeepholeOptimizer.cpp

$(IntermediateDirectory)/SSACallingConvApplier.cpp$(ObjectSuffix): SSACallingConvApplier.cpp $(IntermediateDirectory)/SSACallingConvApplier.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/SSACallingConvApplier.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/SSACallingConvApplier.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/SSACallingConvApplier.cpp$(DependSuffix): SSACallingConvApplier.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/SSACallingConvApplier.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/SSACallingConvApplier.cpp$(DependSuffix) -MM SSACallingConvApplier.cpp

$(IntermediateDirectory)/SSACallingConvApplier.cpp$(PreprocessSuffix): SSACallingConvApplier.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/SSACallingConvApplier.cpp$(PreprocessSuffix) SSACallingConvApplier.cpp

$(IntermediateDirectory)/IRGen.cpp$(ObjectSuffix): IRGen.cpp $(IntermediateDirectory)/IRGen.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/IRGen.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/IRGen.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/IRGen.cpp$(DependSuffix): IRGen.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/IRGen.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/IRGen.cpp$(DependSuffix) -MM IRGen.cpp

$(IntermediateDirectory)/IRGen.cpp$(PreprocessSuffix): IRGen.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/IRGen.cpp$(PreprocessSuffix) IRGen.cpp


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r ./Debug/


