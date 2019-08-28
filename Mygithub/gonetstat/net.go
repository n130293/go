package connectionDependency

import (
	"fmt"
	"io/ioutil"
	"os"
	//"os/user"
	"opsramp/appdetection/shared"
	"opsramp/common/util"
	"opsramp/configuration/agentconfig"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	//"encoding/json"
)

var AgentLog = agentconfig.Log

var proc_path = getProcPath()

var (
	PROC_TCP  = filepath.Join(proc_path,"net/tcp")
	PROC_UDP  = filepath.Join(proc_path,"net/udp")
	PROC_TCP6 = filepath.Join(proc_path,"net/tcp6")
	PROC_UDP6 = filepath.Join(proc_path,"net/udp6")
)

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type ConnectionData shared.ConnectionData

var DirProcGlob []string

// type Data shared.Data

func getData(t string) (lines []string) {
	// Get data from tcp or udp file.

	var proc_t string
	
	if t == "tcp" {
		proc_t = PROC_TCP
	} else if t == "udp" {
		proc_t = PROC_UDP
	} else if t == "tcp6" {
		proc_t = PROC_TCP6
	} else if t == "udp6" {
		proc_t = PROC_UDP6
	} else {
		AgentLog.Error("Method getData received Invalid type")
	}

	data, err := ioutil.ReadFile(proc_t)
	
	if util.HandleError(err, "Error in ioutil.ReadFile in getData, error : ", err) || (string(data) == "") {
		return 
	}
	
	lines = strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	if len(lines) > 1{
		return lines[1 : len(lines)-1]
	}
	return 
}

func hexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	util.HandleError(err)
	return d
}

func convertIp(ip string) (string, string) {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string
	var atype string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v.%v.%v.%v", hexToDec(i[0]), hexToDec(i[1]), hexToDec(i[2]), hexToDec(i[3]))

		atype = "ipv6"

	} else {
		i := []int64{hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
		atype = "ipv4"
	}
	return out, atype
}

func GetDirProcGlob(){
	var err error
	AgentLog.Debug("Proc_path:",proc_path)
	DirProcGlob, err = filepath.Glob(proc_path + "/[0-9]*/fd/[0-9]*")
	util.HandleError(err)
}

func findPid(inode string) string {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.

	pid := "-"

	re := regexp.MustCompile(inode)
	for _, item := range DirProcGlob {
		path, err := os.Readlink(item)
		if err == nil {
			out := re.FindString(path)
			if len(out) != 0 {
				//AgentLog.Debug("item:",item)
				
				if util.IsWorkerAgent {
					pid = strings.Split(item, "/")[3]
				}else{
					pid = strings.Split(item, "/")[2]
				}
			}
		}
	}
	return pid
}

func getProcessExe(pid string) string {
	if pid == "-"{
		return ""
	}
	exe := fmt.Sprintf(proc_path + "/%s/exe", pid)
	path, err := os.Readlink(exe)
	if err !=nil {
		return ""
	}
	//util.HandleError(err, "Exception Occurred at getProcessExe()", err)
	return path
}

func getProcessCmdline(pid string) string {
	/*exe := fmt.Sprintf("/proc/%s/cmdline", pid)
	cmdline, err := os.Readlink(exe)
	util.HandleError(err, "Exception Occurred at getProcessCmdline()", err)
	*/
	if pid == "-"{
		return ""
	}
	cmd := fmt.Sprintf("ps -p %s -o args", pid)
	out, _ := util.ExecutePipeCommand(cmd)
	
	return out
}

func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n)-1]
	return name
}

/*func getUser(uid string) string {
	u, _ := user.LookupId(uid)
	return u.Username
}*/

func removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array []string
	for _, i := range array {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

func InitiateConnectionDependencyCheck(temp_ []string, connectionDepData map[string]shared.Data, PortMap map[string]string) {
	defer func() {
		if errD := recover(); errD != nil {
			AgentLog.Error("Exception Occurred at ", agentconfig.RecoverExceptionDetails(agentconfig.GetParentFunName()), " and Recovered in InitiateConnectionDependencyCheck(), Error Info: ", errD)
		}
	}()

	AgentLog.Debug("Starting Connection dependency scan..")
	var ConnectionDataList []ConnectionData
	GetDirProcGlob()
	for _, proto := range temp_ {
		data := getData(proto)

		for _, line := range data {

			//fmt.Println("line:",line)
			// local ip and port
			line_array := removeEmpty(strings.Split(strings.TrimSpace(line), " "))
			ip_port := strings.Split(line_array[1], ":")
			ip, atype := convertIp(ip_port[0])
			port := hexToDec(ip_port[1])

			//fmt.Println("port:",port)

			// foreign ip and port
			fip_port := strings.Split(line_array[2], ":")
			fip, _ := convertIp(fip_port[0])
			fport := hexToDec(fip_port[1])

			if len (PortMap) > 0 {
				//Filter ports we support in detection
				key := strconv.FormatInt(int64(fport), 10)
				_, okFport := PortMap[key]
	
				key = strconv.FormatInt(int64(port), 10)
				_, okport := PortMap[key]
				if !okFport && !okport {
					continue
				}
			}
			
			state := STATE[line_array[3]]
			//uid := getUser(line_array[7])
			uid := "uid"
			pid := findPid(line_array[9])
			
			
			exe := getProcessExe(pid)
			cmdline := getProcessCmdline(pid)
			name := getProcessName(exe)
			protocal := proto

			val := ConnectionData{User: uid, Name: name, Pid: pid, Exe: exe, State: state, Ip: ip, Port: port, ForeignIp: fip, ForeignPort: fport, Protocal: protocal, AType: atype, CmdLine: cmdline}
			ConnectionDataList = append(ConnectionDataList, val)

		}
	}

	//connectionDepData := make(map[string]shared.Data)
	listen_ := make(map[string]string)
	var CType string
	var SrcIp string
	var DstIp string
	var DstPo int64
	var SrcPo int64

	for _, p := range ConnectionDataList {
		if p.State == "LISTEN" {
			listen_[fmt.Sprintf("%v", p.Port)+"_"+p.Protocal] = p.Ip
		}
	}

	for _, p := range ConnectionDataList {
		if p.State == "LISTEN" {
			_port := fmt.Sprintf("%v", p.Port)
			key := "LISTEN" + "_" + p.AType + "_" + p.Protocal + "_" + p.Ip + "_" + p.ForeignIp + "_" + _port + "_" + p.Name
			_, ok := connectionDepData[key]
			if !ok {
				connectionDepData[key] = shared.Data{CType: "LISTEN", AType: p.AType, PType: p.Protocal, SRCIP: p.Ip, DSTIP: p.ForeignIp, SrvPort: p.Port, SName: p.Name, Count: 1, State: "LISTEN", SrcPort: p.ForeignPort, Pid: p.Pid, BinaryPath: p.Exe, CmdLine: p.CmdLine}
			} else {
				cData := connectionDepData[key]
				cData.Count += 1
				connectionDepData[key] = cData
			}
		} else if p.State == "ESTABLISHED" {
			_port := fmt.Sprintf("%v", p.Port)
			if _, ok := listen_[_port+"_"+p.Protocal];ok {
				if listen_[_port+"_"+p.Protocal] == "0.0.0.0" || listen_[_port+"_"+p.Protocal] == "0000:0000:0000:0000:0000:0000:0000:0000" || listen_[_port+"_"+p.Protocal] == p.Ip {
					SrcIp = p.ForeignIp
					DstIp = p.Ip
					DstPo = p.Port
					SrcPo = p.ForeignPort
					if p.ForeignIp != p.Ip {
						CType = "INCOMING"
					} else {
						CType = "SELF_INCOMING"
					}
				}
			} else {
				//if _,ok := listen_[p.ForeignPort]; !ok && p.ForeignIp != p.Ip{
				SrcIp = p.Ip
				DstIp = p.ForeignIp
				DstPo = p.ForeignPort
				SrcPo = p.Port

				if p.ForeignIp != p.Ip {
					CType = "OUTGOING"
				} else {
					CType = "SELF_OUTGOING"
				}
			}

			_dport := fmt.Sprintf("%v", DstPo)
			key := CType + "_" + p.AType + "_" + p.Protocal + "_" + SrcIp + "_" + DstIp + "_" + _dport + "_" + p.Name
			_, ok := connectionDepData[key]
			if !ok {
				connectionDepData[key] = shared.Data{CType: CType, AType: p.AType, PType: p.Protocal, SRCIP: SrcIp, DSTIP: DstIp, SrvPort: DstPo, SName: p.Name, Count: 1, State: "ESTABLISHED", SrcPort: SrcPo, Pid: p.Pid, BinaryPath: p.Exe, CmdLine: p.CmdLine}
			} else {
				cData := connectionDepData[key]
				cData.Count += 1
				connectionDepData[key] = cData
			}
		} 
	}

}	//fmt.Println("connectionDepData:",connectionDepData)

}

func getProcPath ()string {
	if util.IsWorkerAgent {
		return "/host/proc"
	}
	return "/proc"	
}