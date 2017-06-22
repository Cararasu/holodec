##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=main
ConfigurationName      :=Debug
WorkspacePath          :=E:/GNUProg/radpp
ProjectPath            :=E:/GNUProg/radpp/main
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=Thomas
Date                   :=22/06/2017
CodeLitePath           :="C:/Program Files/CodeLite"
LinkerName             :="C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/g++.exe"
SharedObjectLinkerName :="C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/g++.exe" -shared -fPIC
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
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :="main.txt"
PCHCompileFlags        :=
MakeDirCommand         :=makedir
RcCmpOptions           := 
RcCompilerName         :="C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/windres.exe"
LinkOptions            :=  
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). $(IncludeSwitch)../capstone/include 
IncludePCH             := 
RcIncludePath          := 
Libs                   := $(LibrarySwitch)capstone 
ArLibs                 :=  "libcapstone.a" 
LibPath                := $(LibraryPathSwitch). $(LibraryPathSwitch)..\capstone\build 

##
## Common variables
## AR, CXX, CC, AS, CXXFLAGS and CFLAGS can be overriden using an environment variables
##
AR       := "C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/ar.exe" rcu
CXX      := "C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/g++.exe"
CC       := "C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/gcc.exe"
CXXFLAGS :=  -g -O0 -Wall -std=c++11 $(Preprocessors)
CFLAGS   :=  -g -O0 -Wall $(Preprocessors)
ASFLAGS  := 
AS       := "C:/Program Files/mingw-w64/x86_64-6.2.0-posix-seh-rt_v5-rev1/mingw64/bin/as.exe"


##
## User defined environment variables
##
CodeLiteDir:=C:\Program Files\CodeLite
Objects0=$(IntermediateDirectory)/main.cpp$(ObjectSuffix) $(IntermediateDirectory)/RClass.cpp$(ObjectSuffix) $(IntermediateDirectory)/RSection.cpp$(ObjectSuffix) $(IntermediateDirectory)/RFunction.cpp$(ObjectSuffix) $(IntermediateDirectory)/RBinary.cpp$(ObjectSuffix) $(IntermediateDirectory)/RData.cpp$(ObjectSuffix) $(IntermediateDirectory)/RMain.cpp$(ObjectSuffix) $(IntermediateDirectory)/RGeneral.cpp$(ObjectSuffix) $(IntermediateDirectory)/RString.cpp$(ObjectSuffix) $(IntermediateDirectory)/RConsole.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/RLogger.cpp$(ObjectSuffix) $(IntermediateDirectory)/RFileFormat.cpp$(ObjectSuffix) $(IntermediateDirectory)/RBinaryAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/RFunctionAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/RArchitecture.cpp$(ObjectSuffix) $(IntermediateDirectory)/RInstrDefinition.cpp$(ObjectSuffix) $(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(ObjectSuffix) 



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
	@$(MakeDirCommand) "./Debug"


$(IntermediateDirectory)/.d:
	@$(MakeDirCommand) "./Debug"

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/main.cpp$(ObjectSuffix): main.cpp $(IntermediateDirectory)/main.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/main.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/main.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/main.cpp$(DependSuffix): main.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/main.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/main.cpp$(DependSuffix) -MM main.cpp

$(IntermediateDirectory)/main.cpp$(PreprocessSuffix): main.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/main.cpp$(PreprocessSuffix) main.cpp

$(IntermediateDirectory)/RClass.cpp$(ObjectSuffix): RClass.cpp $(IntermediateDirectory)/RClass.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RClass.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RClass.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RClass.cpp$(DependSuffix): RClass.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RClass.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RClass.cpp$(DependSuffix) -MM RClass.cpp

$(IntermediateDirectory)/RClass.cpp$(PreprocessSuffix): RClass.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RClass.cpp$(PreprocessSuffix) RClass.cpp

$(IntermediateDirectory)/RSection.cpp$(ObjectSuffix): RSection.cpp $(IntermediateDirectory)/RSection.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RSection.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RSection.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RSection.cpp$(DependSuffix): RSection.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RSection.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RSection.cpp$(DependSuffix) -MM RSection.cpp

$(IntermediateDirectory)/RSection.cpp$(PreprocessSuffix): RSection.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RSection.cpp$(PreprocessSuffix) RSection.cpp

$(IntermediateDirectory)/RFunction.cpp$(ObjectSuffix): RFunction.cpp $(IntermediateDirectory)/RFunction.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RFunction.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RFunction.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RFunction.cpp$(DependSuffix): RFunction.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RFunction.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RFunction.cpp$(DependSuffix) -MM RFunction.cpp

$(IntermediateDirectory)/RFunction.cpp$(PreprocessSuffix): RFunction.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RFunction.cpp$(PreprocessSuffix) RFunction.cpp

$(IntermediateDirectory)/RBinary.cpp$(ObjectSuffix): RBinary.cpp $(IntermediateDirectory)/RBinary.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RBinary.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RBinary.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RBinary.cpp$(DependSuffix): RBinary.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RBinary.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RBinary.cpp$(DependSuffix) -MM RBinary.cpp

$(IntermediateDirectory)/RBinary.cpp$(PreprocessSuffix): RBinary.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RBinary.cpp$(PreprocessSuffix) RBinary.cpp

$(IntermediateDirectory)/RData.cpp$(ObjectSuffix): RData.cpp $(IntermediateDirectory)/RData.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RData.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RData.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RData.cpp$(DependSuffix): RData.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RData.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RData.cpp$(DependSuffix) -MM RData.cpp

$(IntermediateDirectory)/RData.cpp$(PreprocessSuffix): RData.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RData.cpp$(PreprocessSuffix) RData.cpp

$(IntermediateDirectory)/RMain.cpp$(ObjectSuffix): RMain.cpp $(IntermediateDirectory)/RMain.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RMain.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RMain.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RMain.cpp$(DependSuffix): RMain.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RMain.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RMain.cpp$(DependSuffix) -MM RMain.cpp

$(IntermediateDirectory)/RMain.cpp$(PreprocessSuffix): RMain.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RMain.cpp$(PreprocessSuffix) RMain.cpp

$(IntermediateDirectory)/RGeneral.cpp$(ObjectSuffix): RGeneral.cpp $(IntermediateDirectory)/RGeneral.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RGeneral.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RGeneral.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RGeneral.cpp$(DependSuffix): RGeneral.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RGeneral.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RGeneral.cpp$(DependSuffix) -MM RGeneral.cpp

$(IntermediateDirectory)/RGeneral.cpp$(PreprocessSuffix): RGeneral.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RGeneral.cpp$(PreprocessSuffix) RGeneral.cpp

$(IntermediateDirectory)/RString.cpp$(ObjectSuffix): RString.cpp $(IntermediateDirectory)/RString.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RString.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RString.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RString.cpp$(DependSuffix): RString.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RString.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RString.cpp$(DependSuffix) -MM RString.cpp

$(IntermediateDirectory)/RString.cpp$(PreprocessSuffix): RString.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RString.cpp$(PreprocessSuffix) RString.cpp

$(IntermediateDirectory)/RConsole.cpp$(ObjectSuffix): RConsole.cpp $(IntermediateDirectory)/RConsole.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RConsole.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RConsole.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RConsole.cpp$(DependSuffix): RConsole.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RConsole.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RConsole.cpp$(DependSuffix) -MM RConsole.cpp

$(IntermediateDirectory)/RConsole.cpp$(PreprocessSuffix): RConsole.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RConsole.cpp$(PreprocessSuffix) RConsole.cpp

$(IntermediateDirectory)/RLogger.cpp$(ObjectSuffix): RLogger.cpp $(IntermediateDirectory)/RLogger.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RLogger.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RLogger.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RLogger.cpp$(DependSuffix): RLogger.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RLogger.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RLogger.cpp$(DependSuffix) -MM RLogger.cpp

$(IntermediateDirectory)/RLogger.cpp$(PreprocessSuffix): RLogger.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RLogger.cpp$(PreprocessSuffix) RLogger.cpp

$(IntermediateDirectory)/RFileFormat.cpp$(ObjectSuffix): RFileFormat.cpp $(IntermediateDirectory)/RFileFormat.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RFileFormat.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RFileFormat.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RFileFormat.cpp$(DependSuffix): RFileFormat.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RFileFormat.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RFileFormat.cpp$(DependSuffix) -MM RFileFormat.cpp

$(IntermediateDirectory)/RFileFormat.cpp$(PreprocessSuffix): RFileFormat.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RFileFormat.cpp$(PreprocessSuffix) RFileFormat.cpp

$(IntermediateDirectory)/RBinaryAnalyzer.cpp$(ObjectSuffix): RBinaryAnalyzer.cpp $(IntermediateDirectory)/RBinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RBinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RBinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RBinaryAnalyzer.cpp$(DependSuffix): RBinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RBinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RBinaryAnalyzer.cpp$(DependSuffix) -MM RBinaryAnalyzer.cpp

$(IntermediateDirectory)/RBinaryAnalyzer.cpp$(PreprocessSuffix): RBinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RBinaryAnalyzer.cpp$(PreprocessSuffix) RBinaryAnalyzer.cpp

$(IntermediateDirectory)/RFunctionAnalyzer.cpp$(ObjectSuffix): RFunctionAnalyzer.cpp $(IntermediateDirectory)/RFunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RFunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RFunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RFunctionAnalyzer.cpp$(DependSuffix): RFunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RFunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RFunctionAnalyzer.cpp$(DependSuffix) -MM RFunctionAnalyzer.cpp

$(IntermediateDirectory)/RFunctionAnalyzer.cpp$(PreprocessSuffix): RFunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RFunctionAnalyzer.cpp$(PreprocessSuffix) RFunctionAnalyzer.cpp

$(IntermediateDirectory)/RArchitecture.cpp$(ObjectSuffix): RArchitecture.cpp $(IntermediateDirectory)/RArchitecture.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RArchitecture.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RArchitecture.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RArchitecture.cpp$(DependSuffix): RArchitecture.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RArchitecture.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RArchitecture.cpp$(DependSuffix) -MM RArchitecture.cpp

$(IntermediateDirectory)/RArchitecture.cpp$(PreprocessSuffix): RArchitecture.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RArchitecture.cpp$(PreprocessSuffix) RArchitecture.cpp

$(IntermediateDirectory)/RInstrDefinition.cpp$(ObjectSuffix): RInstrDefinition.cpp $(IntermediateDirectory)/RInstrDefinition.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RInstrDefinition.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RInstrDefinition.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RInstrDefinition.cpp$(DependSuffix): RInstrDefinition.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RInstrDefinition.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RInstrDefinition.cpp$(DependSuffix) -MM RInstrDefinition.cpp

$(IntermediateDirectory)/RInstrDefinition.cpp$(PreprocessSuffix): RInstrDefinition.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RInstrDefinition.cpp$(PreprocessSuffix) RInstrDefinition.cpp

$(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(ObjectSuffix): RElfBinaryAnalyzer.cpp $(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/RElfBinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(DependSuffix): RElfBinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(DependSuffix) -MM RElfBinaryAnalyzer.cpp

$(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(PreprocessSuffix): RElfBinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/RElfBinaryAnalyzer.cpp$(PreprocessSuffix) RElfBinaryAnalyzer.cpp

$(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(ObjectSuffix): Rx86FunctionAnalyzer.cpp $(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "E:/GNUProg/radpp/main/Rx86FunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(DependSuffix): Rx86FunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(DependSuffix) -MM Rx86FunctionAnalyzer.cpp

$(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(PreprocessSuffix): Rx86FunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Rx86FunctionAnalyzer.cpp$(PreprocessSuffix) Rx86FunctionAnalyzer.cpp


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r ./Debug/


