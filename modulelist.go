package main

type ModuleProcess struct {
	Base       int64
	RegionSize int64
}

type ModuleList struct {
	List      []ModuleProcess
	TotalSize int64
}

func (module *ModuleList) addModule(base int64, size int64) {
	process := ModuleProcess{
		Base:       base,
		RegionSize: size,
	}

	module.List = append(module.List, process)
	module.TotalSize += size
}

func createNewModuleList() ModuleList {
	moduleList := ModuleList{
		List:      []ModuleProcess{},
		TotalSize: 0,
	}

	return moduleList
}