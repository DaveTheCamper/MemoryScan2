package main

import (
	"fmt"
	"github.com/0xrawsec/golang-win32/win32"
	kernel32 "github.com/0xrawsec/golang-win32/win32/kernel32"
	ps "github.com/mitchellh/go-ps"
	windows "golang.org/x/sys/windows"
	"log"
	"math"
	"os"
	"path"
	"sync"
	"time"
)

var wg sync.WaitGroup

const (
	ProcessName = "IQ Option.exe"
	BufferSize  = 50
	MinSize     = 2000000
	Name1       = "{\"name\":\"positions-state\","
	Name2       = "{\"name\":\"heartbeat\",\"msg\":"
	Name3       = "{\"name\":\"candle-generated\",\"microserviceName\":"
	Name4       = "{\"name\":\"traders-mood-changed\","
)

func main() {

	initialTime := time.Now().UnixMilli()
	arrByte := make([]byte, BufferSize)

	process, _ := findProcessByName(ProcessName)

	fmt.Println(process)

	pid := uint32(process.Pid())

	address := searchMemoryAddress(pid)

	s := string(arrByte)

	fmt.Printf("Endereco -> %v", address)
	fmt.Println(s)
	fmt.Printf("Total time %vms", time.Now().UnixMilli()-initialTime)

	saveCache(address.Endereco)
}

func saveCache(endereco int64) {
	f, err := os.Create("cache.txt")

	if err != nil {
		log.Fatal(err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			return
		}
	}(f)

	_, err = fmt.Fprint(f, endereco)

	if err != nil {
		log.Fatal(err)
	}
}

func getProcessBaseAddress(win32handle win32.HANDLE) int64 {
	moduleHandles, _ := kernel32.EnumProcessModules(win32handle)
	for _, moduleHandle := range moduleHandles {
		s, _ := kernel32.GetModuleFilenameExW(win32handle, moduleHandle)

		if path.Base(s) == ProcessName {
			info, _ := kernel32.GetModuleInformation(win32handle, moduleHandle)
			return int64(info.LpBaseOfDll)
		}
	}

	return 0
}

func getProcessHandle(pid uint32) (win32.HANDLE, error) {
	return kernel32.OpenProcess(windows.SERVICE_ALL_ACCESS, win32.BOOL(0), win32.DWORD(pid))
}

func searchMemoryAddress(pid uint32) AddressFound {
	win32handle, _ := getProcessHandle(pid)
	baseProcessAddr := getProcessBaseAddress(win32handle)

	ptrAddr := win32.LPCVOID(baseProcessAddr)
	runningGoRoutines := 0

	foundResults := SafeList{
		List: []AddressFound{},
	}
	moduleList := createNewModuleList()

	for {
		memInfo, err := kernel32.VirtualQueryEx(win32handle, ptrAddr)
		ptrAddr += win32.LPCVOID(memInfo.RegionSize)

		if err != nil {
			break
		}

		if memInfo.State == win32.MEM_COMMIT && memInfo.Protect != win32.PAGE_NOACCESS && memInfo.Protect != win32.PAGE_GUARD {
			moduleList.addModule(int64(memInfo.BaseAddress), int64(memInfo.RegionSize))

			if moduleList.TotalSize >= MinSize {
				createdRoutines := createGoRoutine(pid, moduleList, &foundResults)

				runningGoRoutines += int(createdRoutines)
				moduleList = createNewModuleList()
			}
		}
	}

	if moduleList.TotalSize > 0 {
		createdRoutines := createGoRoutine(pid, moduleList, &foundResults)

		runningGoRoutines += int(createdRoutines)
	}

	wg.Wait()

	if len(foundResults.List) > 0 {
		for {
			time.Sleep(1500 * time.Millisecond)
			totalReady := len(foundResults.List)
			var lastAddress AddressFound

			fmt.Printf("Total ready before: %v\n", totalReady)

			for _, address := range foundResults.List {
				if address.Declined {
					totalReady--
					continue
				}

				readNewWord := make([]byte, 200)
				_, _ = kernel32.ReadProcessMemory(win32handle, win32.LPCVOID(address.Endereco), readNewWord)
				novaPalavra := string(readNewWord)

				if address.Endereco == 294144448 {
					fmt.Printf(novaPalavra)
				}

				if novaPalavra == address.PalavraLog {
					address.Declined = true
					totalReady--
					continue
				} else if !verifyPalavra(Name1, novaPalavra) && !verifyPalavra(Name2, novaPalavra) && !verifyPalavra(Name3, novaPalavra) && !verifyPalavra(Name4, novaPalavra) {
					address.Declined = true
					totalReady--
					continue
				}

				address.PalavraLog = novaPalavra
				lastAddress = address
			}

			fmt.Printf("Total ready: %v\n", totalReady)

			if totalReady == 1 {
				return lastAddress
			} else if totalReady == 0 {
				for _, address := range foundResults.List {
					address.Declined = false
				}
			}
		}
	}

	fmt.Printf("Running rotines -> %v %v\n", int64(runningGoRoutines), len(foundResults.List))

	return AddressFound{
		Endereco: -1,
	}
}

func createGoRoutine(pid uint32, moduleList ModuleList, foundResults *SafeList) int64 {
	totalRoutines := math.Ceil(float64(moduleList.TotalSize) / float64(MinSize))

	for i := 0; i < int(totalRoutines); i++ {
		wg.Add(1)
		go findWord(pid, int64(i), int64(totalRoutines), moduleList, foundResults)
	}

	//fmt.Printf("VirtualQuery -> %v -> %v\n", moduleList.TotalSize, moduleList.List)

	return int64(totalRoutines)
}

type SafeList struct {
	mu   sync.Mutex
	List []AddressFound
}

type AddressFound struct {
	Declined   bool
	Endereco   int64
	PalavraLog string
}

func findWord(pid uint32, routineId int64, totalRoutines int64, moduleList ModuleList, foundResults *SafeList) {
	processHandle, _ := getProcessHandle(pid)

	for _, moduleProcess := range moduleList.List {

		particinamento := moduleProcess.RegionSize / totalRoutines

		current := moduleProcess.Base + (particinamento * routineId)
		end := moduleProcess.Base + (particinamento * (routineId + 1))

		arrByte := make([]byte, particinamento)
		palavra := "{\"name\":"

		_, _ = kernel32.ReadProcessMemory(processHandle, win32.LPCVOID(current), arrByte)
		s := string(arrByte)
		i := 0
		memoryIndex := 0

		for ; current < end; current++ {

			/*if current <= 294144448 && end >= 294144448 {
				fmt.Printf("End aqui %v\n", current)
			}*/

			if s[memoryIndex] == palavra[i] {
				i++
				if i == len(palavra) || current == end-1 {

					tempBytes := make([]byte, 200)
					realEndereco := current - int64(len(palavra)-1)

					_, _ = kernel32.ReadProcessMemory(processHandle, win32.LPCVOID(realEndereco), tempBytes)

					foundResults.mu.Lock()

					foundResults.List = append(foundResults.List, AddressFound{
						Declined:   false,
						Endereco:   realEndereco,
						PalavraLog: string(tempBytes),
					})
					foundResults.mu.Unlock()

					fmt.Printf("Encontrado added -> %v\n", current-int64(len(palavra)-1))
					i = 0
				}
			} else {
				i = 0
			}

			memoryIndex++
		}
	}

	defer wg.Done()
}

func verifyPalavra(palavra string, inMemory string) bool {
	found := true
	i := 0

	for ; i < len(palavra); i++ {
		if palavra[i] != inMemory[i] {
			found = false
			break
		}
	}

	return found
}

func findProcessByName(name string) (ps.Process, error) {
	processes, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	for _, process := range processes {
		if process.Executable() == name {
			return process, nil
		}
	}

	return nil, nil
}
