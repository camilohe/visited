##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Debug
ProjectName            :=visited
ConfigurationName      :=Debug
IntermediateDirectory  :=./Debug
OutDir                 := $(IntermediateDirectory)
WorkspacePath          := "S:\Projects\CodeLite\visited"
ProjectPath            := "S:\Projects\CodeLite\visited"
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=administrator
Date                   :=04/21/11
CodeLitePath           :="C:\Programs\CodeLite"
LinkerName             :=gcc
ArchiveTool            :=ar rcus
SharedObjectLinkerName :=gcc -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.o.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
CompilerName           :=gcc
C_CompilerName         :=gcc
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E 
ObjectsFileList        :="S:\Projects\CodeLite\visited\visited.txt"
MakeDirCommand         :=makedir
CmpOptions             := -g $(Preprocessors)
C_CmpOptions           := -g $(Preprocessors)
LinkOptions            :=  
IncludePath            :=  $(IncludeSwitch). $(IncludeSwitch). 
RcIncludePath          :=
Libs                   :=
LibPath                := $(LibraryPathSwitch). 


##
## User defined environment variables
##
CodeLiteDir:=C:\Programs\CodeLite
UNIT_TEST_PP_SRC_DIR:=C:\Programs\UnitTest++-1.3
Objects=$(IntermediateDirectory)/aht$(ObjectSuffix) $(IntermediateDirectory)/antigetopt$(ObjectSuffix) $(IntermediateDirectory)/tail$(ObjectSuffix) $(IntermediateDirectory)/visited$(ObjectSuffix) 

##
## Main Build Targets 
##
all: $(OutputFile)

$(OutputFile): makeDirStep $(Objects)
	@$(MakeDirCommand) $(@D)
	$(LinkerName) $(OutputSwitch)$(OutputFile) $(Objects) $(LibPath) $(Libs) $(LinkOptions)

objects_file:
	@echo $(Objects) > $(ObjectsFileList)

makeDirStep:
	@$(MakeDirCommand) "./Debug"

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/aht$(ObjectSuffix): aht.c $(IntermediateDirectory)/aht$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "S:/Projects/CodeLite/visited/aht.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/aht$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/aht$(DependSuffix): aht.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/aht$(ObjectSuffix) -MF$(IntermediateDirectory)/aht$(DependSuffix) -MM "S:/Projects/CodeLite/visited/aht.c"

$(IntermediateDirectory)/aht$(PreprocessSuffix): aht.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/aht$(PreprocessSuffix) "S:/Projects/CodeLite/visited/aht.c"

$(IntermediateDirectory)/antigetopt$(ObjectSuffix): antigetopt.c $(IntermediateDirectory)/antigetopt$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "S:/Projects/CodeLite/visited/antigetopt.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/antigetopt$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/antigetopt$(DependSuffix): antigetopt.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/antigetopt$(ObjectSuffix) -MF$(IntermediateDirectory)/antigetopt$(DependSuffix) -MM "S:/Projects/CodeLite/visited/antigetopt.c"

$(IntermediateDirectory)/antigetopt$(PreprocessSuffix): antigetopt.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/antigetopt$(PreprocessSuffix) "S:/Projects/CodeLite/visited/antigetopt.c"

$(IntermediateDirectory)/tail$(ObjectSuffix): tail.c $(IntermediateDirectory)/tail$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "S:/Projects/CodeLite/visited/tail.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/tail$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/tail$(DependSuffix): tail.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/tail$(ObjectSuffix) -MF$(IntermediateDirectory)/tail$(DependSuffix) -MM "S:/Projects/CodeLite/visited/tail.c"

$(IntermediateDirectory)/tail$(PreprocessSuffix): tail.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/tail$(PreprocessSuffix) "S:/Projects/CodeLite/visited/tail.c"

$(IntermediateDirectory)/visited$(ObjectSuffix): visited.c $(IntermediateDirectory)/visited$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "S:/Projects/CodeLite/visited/visited.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/visited$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/visited$(DependSuffix): visited.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/visited$(ObjectSuffix) -MF$(IntermediateDirectory)/visited$(DependSuffix) -MM "S:/Projects/CodeLite/visited/visited.c"

$(IntermediateDirectory)/visited$(PreprocessSuffix): visited.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/visited$(PreprocessSuffix) "S:/Projects/CodeLite/visited/visited.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) $(IntermediateDirectory)/aht$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/aht$(DependSuffix)
	$(RM) $(IntermediateDirectory)/aht$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/antigetopt$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/antigetopt$(DependSuffix)
	$(RM) $(IntermediateDirectory)/antigetopt$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/tail$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/tail$(DependSuffix)
	$(RM) $(IntermediateDirectory)/tail$(PreprocessSuffix)
	$(RM) $(IntermediateDirectory)/visited$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/visited$(DependSuffix)
	$(RM) $(IntermediateDirectory)/visited$(PreprocessSuffix)
	$(RM) $(OutputFile)
	$(RM) $(OutputFile).exe


