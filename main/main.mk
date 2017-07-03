##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=main
ConfigurationName      :=Debug
WorkspacePath          := "/home/thomas/Prog/holodec"
ProjectPath            := "/home/thomas/Prog/holodec/main"
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=thomas
Date                   :=02/07/17
CodeLitePath           :="/home/thomas/.codelite"
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
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E
ObjectsFileList        :="main.txt"
PCHCompileFlags        :=
MakeDirCommand         :=mkdir -p
LinkOptions            :=  
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). $(IncludeSwitch)../capstone/include $(IncludeSwitch)../cpython/Include 
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
CXXFLAGS := -Wall -std=c++11 -g -O0 $(Preprocessors)
CFLAGS   := -Wall -std=c99 -g -O0 $(Preprocessors)
ASFLAGS  := 
AS       := /usr/bin/as


##
## User defined environment variables
##
CodeLiteDir:=/usr/share/codelite
Objects0=$(IntermediateDirectory)/main.cpp$(ObjectSuffix) $(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix) $(IntermediateDirectory)/HSection.cpp$(ObjectSuffix) $(IntermediateDirectory)/HFunction.cpp$(ObjectSuffix) $(IntermediateDirectory)/HData.cpp$(ObjectSuffix) $(IntermediateDirectory)/HClass.cpp$(ObjectSuffix) $(IntermediateDirectory)/HBinary.cpp$(ObjectSuffix) $(IntermediateDirectory)/HScriptingInterface.cpp$(ObjectSuffix) $(IntermediateDirectory)/HMain.cpp$(ObjectSuffix) $(IntermediateDirectory)/HLogger.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/HGeneral.cpp$(ObjectSuffix) $(IntermediateDirectory)/HConsole.cpp$(ObjectSuffix) $(IntermediateDirectory)/HoloIR.cpp$(ObjectSuffix) $(IntermediateDirectory)/HoloSSA.cpp$(ObjectSuffix) $(IntermediateDirectory)/HBinaryAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/HFileFormat.cpp$(ObjectSuffix) $(IntermediateDirectory)/HInstrDefinition.cpp$(ObjectSuffix) $(IntermediateDirectory)/HFunctionAnalyzer.cpp$(ObjectSuffix) $(IntermediateDirectory)/HArchitecture.cpp$(ObjectSuffix) $(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(ObjectSuffix) \
	$(IntermediateDirectory)/Hx86Architecture.cpp$(ObjectSuffix) $(IntermediateDirectory)/HElfDataFile.cpp$(ObjectSuffix) $(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(ObjectSuffix) 



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
$(IntermediateDirectory)/main.cpp$(ObjectSuffix): main.cpp $(IntermediateDirectory)/main.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/main.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/main.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/main.cpp$(DependSuffix): main.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/main.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/main.cpp$(DependSuffix) -MM "main.cpp"

$(IntermediateDirectory)/main.cpp$(PreprocessSuffix): main.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/main.cpp$(PreprocessSuffix) "main.cpp"

$(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix): HStringDatabase.cpp $(IntermediateDirectory)/HStringDatabase.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HStringDatabase.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HStringDatabase.cpp$(DependSuffix): HStringDatabase.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HStringDatabase.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HStringDatabase.cpp$(DependSuffix) -MM "HStringDatabase.cpp"

$(IntermediateDirectory)/HStringDatabase.cpp$(PreprocessSuffix): HStringDatabase.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HStringDatabase.cpp$(PreprocessSuffix) "HStringDatabase.cpp"

$(IntermediateDirectory)/HSection.cpp$(ObjectSuffix): HSection.cpp $(IntermediateDirectory)/HSection.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HSection.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HSection.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HSection.cpp$(DependSuffix): HSection.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HSection.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HSection.cpp$(DependSuffix) -MM "HSection.cpp"

$(IntermediateDirectory)/HSection.cpp$(PreprocessSuffix): HSection.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HSection.cpp$(PreprocessSuffix) "HSection.cpp"

$(IntermediateDirectory)/HFunction.cpp$(ObjectSuffix): HFunction.cpp $(IntermediateDirectory)/HFunction.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HFunction.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HFunction.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HFunction.cpp$(DependSuffix): HFunction.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HFunction.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HFunction.cpp$(DependSuffix) -MM "HFunction.cpp"

$(IntermediateDirectory)/HFunction.cpp$(PreprocessSuffix): HFunction.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HFunction.cpp$(PreprocessSuffix) "HFunction.cpp"

$(IntermediateDirectory)/HData.cpp$(ObjectSuffix): HData.cpp $(IntermediateDirectory)/HData.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HData.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HData.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HData.cpp$(DependSuffix): HData.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HData.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HData.cpp$(DependSuffix) -MM "HData.cpp"

$(IntermediateDirectory)/HData.cpp$(PreprocessSuffix): HData.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HData.cpp$(PreprocessSuffix) "HData.cpp"

$(IntermediateDirectory)/HClass.cpp$(ObjectSuffix): HClass.cpp $(IntermediateDirectory)/HClass.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HClass.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HClass.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HClass.cpp$(DependSuffix): HClass.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HClass.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HClass.cpp$(DependSuffix) -MM "HClass.cpp"

$(IntermediateDirectory)/HClass.cpp$(PreprocessSuffix): HClass.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HClass.cpp$(PreprocessSuffix) "HClass.cpp"

$(IntermediateDirectory)/HBinary.cpp$(ObjectSuffix): HBinary.cpp $(IntermediateDirectory)/HBinary.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HBinary.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HBinary.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HBinary.cpp$(DependSuffix): HBinary.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HBinary.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HBinary.cpp$(DependSuffix) -MM "HBinary.cpp"

$(IntermediateDirectory)/HBinary.cpp$(PreprocessSuffix): HBinary.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HBinary.cpp$(PreprocessSuffix) "HBinary.cpp"

$(IntermediateDirectory)/HScriptingInterface.cpp$(ObjectSuffix): HScriptingInterface.cpp $(IntermediateDirectory)/HScriptingInterface.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HScriptingInterface.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HScriptingInterface.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HScriptingInterface.cpp$(DependSuffix): HScriptingInterface.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HScriptingInterface.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HScriptingInterface.cpp$(DependSuffix) -MM "HScriptingInterface.cpp"

$(IntermediateDirectory)/HScriptingInterface.cpp$(PreprocessSuffix): HScriptingInterface.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HScriptingInterface.cpp$(PreprocessSuffix) "HScriptingInterface.cpp"

$(IntermediateDirectory)/HMain.cpp$(ObjectSuffix): HMain.cpp $(IntermediateDirectory)/HMain.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HMain.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HMain.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HMain.cpp$(DependSuffix): HMain.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HMain.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HMain.cpp$(DependSuffix) -MM "HMain.cpp"

$(IntermediateDirectory)/HMain.cpp$(PreprocessSuffix): HMain.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HMain.cpp$(PreprocessSuffix) "HMain.cpp"

$(IntermediateDirectory)/HLogger.cpp$(ObjectSuffix): HLogger.cpp $(IntermediateDirectory)/HLogger.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HLogger.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HLogger.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HLogger.cpp$(DependSuffix): HLogger.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HLogger.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HLogger.cpp$(DependSuffix) -MM "HLogger.cpp"

$(IntermediateDirectory)/HLogger.cpp$(PreprocessSuffix): HLogger.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HLogger.cpp$(PreprocessSuffix) "HLogger.cpp"

$(IntermediateDirectory)/HGeneral.cpp$(ObjectSuffix): HGeneral.cpp $(IntermediateDirectory)/HGeneral.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HGeneral.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HGeneral.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HGeneral.cpp$(DependSuffix): HGeneral.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HGeneral.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HGeneral.cpp$(DependSuffix) -MM "HGeneral.cpp"

$(IntermediateDirectory)/HGeneral.cpp$(PreprocessSuffix): HGeneral.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HGeneral.cpp$(PreprocessSuffix) "HGeneral.cpp"

$(IntermediateDirectory)/HConsole.cpp$(ObjectSuffix): HConsole.cpp $(IntermediateDirectory)/HConsole.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HConsole.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HConsole.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HConsole.cpp$(DependSuffix): HConsole.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HConsole.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HConsole.cpp$(DependSuffix) -MM "HConsole.cpp"

$(IntermediateDirectory)/HConsole.cpp$(PreprocessSuffix): HConsole.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HConsole.cpp$(PreprocessSuffix) "HConsole.cpp"

$(IntermediateDirectory)/HoloIR.cpp$(ObjectSuffix): HoloIR.cpp $(IntermediateDirectory)/HoloIR.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HoloIR.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HoloIR.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HoloIR.cpp$(DependSuffix): HoloIR.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HoloIR.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HoloIR.cpp$(DependSuffix) -MM "HoloIR.cpp"

$(IntermediateDirectory)/HoloIR.cpp$(PreprocessSuffix): HoloIR.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HoloIR.cpp$(PreprocessSuffix) "HoloIR.cpp"

$(IntermediateDirectory)/HoloSSA.cpp$(ObjectSuffix): HoloSSA.cpp $(IntermediateDirectory)/HoloSSA.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HoloSSA.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HoloSSA.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HoloSSA.cpp$(DependSuffix): HoloSSA.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HoloSSA.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HoloSSA.cpp$(DependSuffix) -MM "HoloSSA.cpp"

$(IntermediateDirectory)/HoloSSA.cpp$(PreprocessSuffix): HoloSSA.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HoloSSA.cpp$(PreprocessSuffix) "HoloSSA.cpp"

$(IntermediateDirectory)/HBinaryAnalyzer.cpp$(ObjectSuffix): HBinaryAnalyzer.cpp $(IntermediateDirectory)/HBinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HBinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HBinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HBinaryAnalyzer.cpp$(DependSuffix): HBinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HBinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HBinaryAnalyzer.cpp$(DependSuffix) -MM "HBinaryAnalyzer.cpp"

$(IntermediateDirectory)/HBinaryAnalyzer.cpp$(PreprocessSuffix): HBinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HBinaryAnalyzer.cpp$(PreprocessSuffix) "HBinaryAnalyzer.cpp"

$(IntermediateDirectory)/HFileFormat.cpp$(ObjectSuffix): HFileFormat.cpp $(IntermediateDirectory)/HFileFormat.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HFileFormat.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HFileFormat.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HFileFormat.cpp$(DependSuffix): HFileFormat.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HFileFormat.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HFileFormat.cpp$(DependSuffix) -MM "HFileFormat.cpp"

$(IntermediateDirectory)/HFileFormat.cpp$(PreprocessSuffix): HFileFormat.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HFileFormat.cpp$(PreprocessSuffix) "HFileFormat.cpp"

$(IntermediateDirectory)/HInstrDefinition.cpp$(ObjectSuffix): HInstrDefinition.cpp $(IntermediateDirectory)/HInstrDefinition.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HInstrDefinition.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HInstrDefinition.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HInstrDefinition.cpp$(DependSuffix): HInstrDefinition.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HInstrDefinition.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HInstrDefinition.cpp$(DependSuffix) -MM "HInstrDefinition.cpp"

$(IntermediateDirectory)/HInstrDefinition.cpp$(PreprocessSuffix): HInstrDefinition.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HInstrDefinition.cpp$(PreprocessSuffix) "HInstrDefinition.cpp"

$(IntermediateDirectory)/HFunctionAnalyzer.cpp$(ObjectSuffix): HFunctionAnalyzer.cpp $(IntermediateDirectory)/HFunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HFunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HFunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HFunctionAnalyzer.cpp$(DependSuffix): HFunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HFunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HFunctionAnalyzer.cpp$(DependSuffix) -MM "HFunctionAnalyzer.cpp"

$(IntermediateDirectory)/HFunctionAnalyzer.cpp$(PreprocessSuffix): HFunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HFunctionAnalyzer.cpp$(PreprocessSuffix) "HFunctionAnalyzer.cpp"

$(IntermediateDirectory)/HArchitecture.cpp$(ObjectSuffix): HArchitecture.cpp $(IntermediateDirectory)/HArchitecture.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HArchitecture.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HArchitecture.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HArchitecture.cpp$(DependSuffix): HArchitecture.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HArchitecture.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HArchitecture.cpp$(DependSuffix) -MM "HArchitecture.cpp"

$(IntermediateDirectory)/HArchitecture.cpp$(PreprocessSuffix): HArchitecture.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HArchitecture.cpp$(PreprocessSuffix) "HArchitecture.cpp"

$(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(ObjectSuffix): Hx86FunctionAnalyzer.cpp $(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Hx86FunctionAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(DependSuffix): Hx86FunctionAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(DependSuffix) -MM "Hx86FunctionAnalyzer.cpp"

$(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(PreprocessSuffix): Hx86FunctionAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Hx86FunctionAnalyzer.cpp$(PreprocessSuffix) "Hx86FunctionAnalyzer.cpp"

$(IntermediateDirectory)/Hx86Architecture.cpp$(ObjectSuffix): Hx86Architecture.cpp $(IntermediateDirectory)/Hx86Architecture.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/Hx86Architecture.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/Hx86Architecture.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/Hx86Architecture.cpp$(DependSuffix): Hx86Architecture.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/Hx86Architecture.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/Hx86Architecture.cpp$(DependSuffix) -MM "Hx86Architecture.cpp"

$(IntermediateDirectory)/Hx86Architecture.cpp$(PreprocessSuffix): Hx86Architecture.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/Hx86Architecture.cpp$(PreprocessSuffix) "Hx86Architecture.cpp"

$(IntermediateDirectory)/HElfDataFile.cpp$(ObjectSuffix): HElfDataFile.cpp $(IntermediateDirectory)/HElfDataFile.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HElfDataFile.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HElfDataFile.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HElfDataFile.cpp$(DependSuffix): HElfDataFile.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HElfDataFile.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HElfDataFile.cpp$(DependSuffix) -MM "HElfDataFile.cpp"

$(IntermediateDirectory)/HElfDataFile.cpp$(PreprocessSuffix): HElfDataFile.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HElfDataFile.cpp$(PreprocessSuffix) "HElfDataFile.cpp"

$(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(ObjectSuffix): HElfBinaryAnalyzer.cpp $(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(DependSuffix)
	$(CXX) $(IncludePCH) $(SourceSwitch) "/home/thomas/Prog/holodec/main/HElfBinaryAnalyzer.cpp" $(CXXFLAGS) $(ObjectSwitch)$(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(DependSuffix): HElfBinaryAnalyzer.cpp
	@$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(ObjectSuffix) -MF$(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(DependSuffix) -MM "HElfBinaryAnalyzer.cpp"

$(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(PreprocessSuffix): HElfBinaryAnalyzer.cpp
	$(CXX) $(CXXFLAGS) $(IncludePCH) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/HElfBinaryAnalyzer.cpp$(PreprocessSuffix) "HElfBinaryAnalyzer.cpp"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) -r ./Debug/


