package main


import (
	"os"
	"os/exec"
	"fmt"
	"net/http"
	"crypto/md5"
	"io"
	"io/ioutil"
	"time"
	"strings"
	"encoding/xml"
)
var authkey string

type SPAConfig struct {
  AuthKey    string
}


func scanrepo(reponame string) {
	rescanarg := fmt.Sprintf("asnp veeampssnapin;Get-VBRBackupRepository | ? { $_.name -match '%s' } | sync-VBRBackupRepository",reponame)
	cmd := exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-c",rescanarg )
	cmd.Start()
	cmd.Wait()
}

func spahandler(w http.ResponseWriter, r *http.Request) {
    tokenverification := r.URL.Path[len("/spa/"):]
    if tokenverification != "" && testtoken(authkey,tokenverification) {
	r.ParseForm()
	fmt.Fprintf(w, "Got validation with %s", tokenverification)
	if cmdvalarr,ok := r.PostForm["cmd"];ok {
		if cmdval := strings.Join(cmdvalarr," ");cmdval != "" {
			parameters := ""
			if parametersvalarr,ok := r.PostForm["param"];ok {
				parameters = strings.Join(parametersvalarr," ")
			}
			switch cmdval {
				case "rescan": {
					if parameters != "" {
						scanrepo(parameters)
						fmt.Fprintf(w,".. rescan executed")
					} else {
						fmt.Fprintf(w,".. need repository")	
					}
				}
				default: fmt.Fprintf(w,".. unknown command")
			}
		} else {
			fmt.Fprintf(w, ".. but don't like empty command",)	
		}
	} else {
		fmt.Fprintf(w, ".. but not command was given",)
	}
    } else {
	fmt.Fprintf(w, "Could not validate token %s",tokenverification)
    }
}

func mainhandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><head><title>post</title><body><form name='dynform' onsubmit='document.dynform.action = \"/spa/\"+document.dynform.token.value ;return true' method='post'><table>")
	fmt.Fprintf(w, "<tr><td>token : </td><td><input name='token' value='' size='50'/></td></tr>")
	fmt.Fprintf(w, "<tr><td>cmd : </td><td><input name='cmd' size='50'/></td></tr>")
	fmt.Fprintf(w, "<tr><td>param : </td><td><input name='param' size='50'/></td></tr>")
	fmt.Fprintf(w, "<tr><td colspan=2><input type='Submit' value='exec'></tr></table></form></body></html>")
}
func testtoken (hash string,token string) (bool) {
	success := false

	if(len(token) > 3) {
		t := time.Now()
		unixtime := (t.Unix())
		
		clienttoken := token[0:2]
		datetoken := token[2:]
	
	
		currentinterval := unixtime - (unixtime%(60*1)) - (60*1)
		for i := 0; i < 3; i++ {
			h := md5.New()
			inhash := fmt.Sprintf("%s supersimpleauth %d %s",hash,currentinterval,clienttoken)
			io.WriteString(h,inhash)
			result := fmt.Sprintf("%x", h.Sum(nil))
		
			if result == datetoken {
				success = true
			}
			currentinterval = currentinterval + (60*1)
		}	
		
	}
	
	return success
}
func generatetoken (hash string) (token string) {
	t := time.Now()
	unixtime := (t.Unix())
	currentinterval := unixtime - (unixtime%(60*1))
	clientcounter := unixtime%67+22

	h := md5.New()
	inhash := fmt.Sprintf("%s supersimpleauth %d %d",hash,currentinterval,clientcounter)
	io.WriteString(h,inhash)
	result := fmt.Sprintf("%x", h.Sum(nil))
	return fmt.Sprintf("%d%s",clientcounter,result)
}

func generatekey () (string) {
	h := md5.New()
	io.WriteString(h, "Salty hash")
	
	hostname,err := os.Hostname()
	if err == nil {
		io.WriteString(h, hostname)
	}
	t := time.Now()
    	io.WriteString(h,t.Format(time.RFC3339))
	return fmt.Sprintf("%x", h.Sum(nil))
}
func Exists(name string) bool {
    if _, err := os.Stat(name); err != nil {
    if os.IsNotExist(err) {
                return false
            }
    }
    return true
}
func getconfig () (*SPAConfig) {
	spaconfig := new(SPAConfig)
	filename := os.ExpandEnv("${programdata}\\spaconfigfile.cfg")
	create := true
	if Exists(filename) {
		xmlbytes, err := ioutil.ReadFile(filename) // For read access.
		if err == nil {
			err = xml.Unmarshal(xmlbytes, &spaconfig)
			if err == nil {
				create = false
			} 
		}	
	}
	if create {
		spaconfig.AuthKey = generatekey()
		x, err := xml.MarshalIndent(spaconfig, "", "")
		_ = err

		f, err := os.Create(filename)
		f.Write(x)
		f.Close()
		
	}
	return spaconfig
}
func main() {
	spaconfigptr := getconfig()
	authkey = spaconfigptr.AuthKey
	

	http.HandleFunc("/", mainhandler)
	http.HandleFunc("/spa/", spahandler)
	http.ListenAndServe(":14041", nil)
}