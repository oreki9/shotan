package main
// code to download shodan data
// paging is not always return 10 data but 2 data each from 5 source
// SELECT l.`ipaddress` 
// FROM `listgeneralinfo` l
// INNER JOIN `generalinfo` g ON l.`generalinfoid` = g.`generalinfoId`
// WHERE g.`title` LIKE '%isp%' GROUP BY `ipaddress` HAVING COUNT(*) > 1
// LIMIT 2 OFFSET 0;

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"
	"errors"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"encoding/json"
)

var baseURL = "https://www.shodan.io"
var resumeWorkURL = "http://localhost:5000"
var idproject = "332"
var ipAddressNow = ""
type Response struct {
	ResponseCode string `json:"responseCode"`
	IDProject    string `json:"idproject"`
	IDTask       string `json:"idtask"`
	TaskDesc     string `json:"taskdesc"`
}
func main() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Println("Error creating cookie jar:", err)
		return
	}
	client := &http.Client{
		Jar: jar,
	}
	// _, err = http.NewRequest("GET", baseURL, nil)
	// if err != nil {
	// 	fmt.Println("Error creating request:", err)
	// 	return
	// }
	fmt.Println("start scrapping")
	workData := getResumeWork(client)
	fmt.Println("check task data"+workData.TaskDesc)
	parts := strings.Split(workData.TaskDesc, "-")
	if len(parts)<2{
		return;
	}
	start := parts[0]
	end := parts[1]
	// Set up a channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run the download function in a goroutine
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- downloadAllPages(client, start, end)
	}()
	idproject := workData.IDProject
	isdone := "false"
	idtask := workData.IDTask
	select {
	case err := <-doneChan:
		isdone := "true"
		taskinput := ipAddressNow+"-"+end
		if err != nil {
			if err.Error() == "session ended" {
				isdone = "false"
				saveWork(client, idproject, isdone, idtask, taskinput)
			}
			fmt.Println("Error:", err)
			return;
		}
		saveWork(client, idproject, isdone, idtask, taskinput)
	case sig := <-sigChan:
		taskinput := ipAddressNow+"-"+end
		saveWork(client, idproject, isdone, idtask, taskinput)
		fmt.Println("test Received signal:", sig)
	}
}
func saveWork(client *http.Client, idproject string, isdone string, idtask string, taskinput string) string {
	req, err := http.NewRequest("GET", resumeWorkURL+"/save?idproject="+idproject+"&isdone="+isdone+"&idtask="+idtask+"&taskinput="+taskinput, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return ""
	}
	defer resp.Body.Close()
	if(resp.StatusCode==200){
		body, _ := ioutil.ReadAll(resp.Body)
		return string(body)
	}else{
		return ""
	}
}
func fetchWork(client *http.Client) string {
	req, err := http.NewRequest("GET", resumeWorkURL+"/resume?idproject="+idproject+"&idtask=c", nil)
	// req.AddCookie(&http.Cookie{Name: "polito", Value: "a53485160aa2b365bfb446d1a934a87e664a08b8621139f0633e38313662868c!"})
	if err != nil {
		fmt.Println("Error creating request:", err)
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return ""
	}
	defer resp.Body.Close()
	if(resp.StatusCode==200){
		body, _ := ioutil.ReadAll(resp.Body)
		return string(body)
	}else{
		return ""
	}
}
func getResumeWork(client *http.Client) Response {
	jsonString := fetchWork(client)
	var response Response
	fmt.Println("check parsing "+jsonString)
	err := json.Unmarshal([]byte(jsonString), &response)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return response
	}
	return response
}
func fetchHtmlString(client *http.Client, ipaddress string) (body string, isclose bool) {
	req, err := http.NewRequest("GET", baseURL+"/host/"+ipaddress, nil)
	req.Header.Set("Cookie", `polito="419cafd44bb6683527726763ea5eedba67d50385621139f0633e38313662868c!"`)
	req.Header.Set("Sec-Ch-Ua", `"Not:A-Brand";v="99", "Chromium";v="112"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36`)
	req.Header.Set("Accept", `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Host = "www.shodan.io"
	if err != nil {
		fmt.Println("Error creating request:", err)
		return "", true
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return "", true
	}
	defer resp.Body.Close()
	if(resp.StatusCode==200){
		body, err := ioutil.ReadAll(resp.Body)
		bodyStr := string(body)
		if(strings.Contains(bodyStr, "No information available for")){
			return "", false
		}else if(strings.Contains(bodyStr, "<a href=\"/dashboard\" class=\"highlight-success\">Login</a>")){
			return "", true
		}else{
			if err != nil {
				fmt.Println("Error reading response body:", err)
				return "", false
			}
			return bodyStr, false
		}
	}else{
		return "", false
	}
}
func convertIPToSlice(ip string) ([]int, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid IP address format")
	}
	ipSlice := make([]int, 4)
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		ipSlice[i] = num
	}
	return ipSlice, nil
}

func convertSliceToIP(ipSlice []int) string {
	parts := make([]string, 4)
	for i, num := range ipSlice {
		parts[i] = strconv.Itoa(num)
	}
	return strings.Join(parts, ".")
}

func incrementIP(ipSlice []int) {
	for i := len(ipSlice) - 1; i >= 0; i-- {
		ipSlice[i]++
		if ipSlice[i] > 255 {
			ipSlice[i] = 1
		} else {
			break
		}
	}
}

func compareIPs(ip1, ip2 []int) bool {
	for i := 0; i < len(ip1); i++ {
		if ip1[i] != ip2[i] {
			return false
		}
	}
	return true
}
func delay(duration time.Duration) {
	time.Sleep(duration)
}
func downloadAllPages(client *http.Client ,start, end string) error {
	startIP, err := convertIPToSlice(start)
	if err != nil {
		return err
	}
	endIP, err := convertIPToSlice(end)
	if err != nil {
		return err
	}	
	for {
		// Convert the current IP slice to an IP address string
		ipAddress := convertSliceToIP(startIP)
		ipAddressNow = ipAddress
		// Perform the HTTP request
		fmt.Println("get client "+ipAddress)
		stringResponse, isclose := fetchHtmlString(client, ipAddress)
		if(isclose){
			err := errors.New("session ended")
			return err
		}
		if(stringResponse != ""){
			// resp.StatusCode
			errorCheck := saveStringToFile(ipAddress+".html", stringResponse)
			if(errorCheck != nil){
				fmt.Println("failed to saved")
			}else{
				fmt.Println("saved page to file")
			}
		}
		// Delay for 1 second
		// delay(100 * time.Millisecond)
		// Increment the IP address
		incrementIP(startIP)
		// Check if we have reached the end IP
		if compareIPs(startIP, endIP) {
			break
		}
	}
	return nil
}
func saveStringToFile(filename, content string) error {
	// check folder
	file, err := os.Create("shodan/file_"+filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content)
	if err != nil {
		return err
	}
	return nil
}
// todo: add cookie checker if cookie is expired then user need login, then stop for a moments
// todo: add save to html
// todo: add loop to iterate array of ip address
