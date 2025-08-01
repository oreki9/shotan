package main

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
	"net/url"
	"os"
	"regexp"
	// "encoding/json"
	"flag"
	"fmt"
	"github.com/gocolly/colly/v2"
	"log"
	"math/rand"
	"time"
	"bytes"
	"encoding/json"
	// "strings"
	en "github.com/oreki9/shotan/Entity"
	customutil "github.com/oreki9/shotan/Utils"
	"database/sql"
    _ "github.com/go-sql-driver/mysql"
	"github.com/PuerkitoBio/goquery"
)
// add check and update when ipaddress is inside database
func main() {
	ipaddress := flag.String("ipaddress", "109.206.245.168", "ip address target")
	folderurl := flag.String("url", "http://localhost/shotan/shodan%202/", "ip address target")
	mode := flag.String("mode", "fetchallas", "ip address target")
	//mode: fetch, fetchall, detail, delete, deleteall
	flag.Parse()
	
	db, err := sql.Open("mysql", "root:@(127.0.0.1:3306)/shotan")
    defer db.Close()
	if err != nil {
		log.Fatal(err)
    }
	ipaddressStr := *ipaddress
	flagMode := *mode
	if (checkAllTable(db, "shotan")){
		fmt.Println("database is not perfect, now in progress")
	}else{
		fmt.Println("database is perfect")
		fmt.Println(ipaddressStr)
	}
	switch(flagMode){
	case "fetchall":
		// TODO: add pause and resume 
		crawlall(db, *folderurl)
	case "fetch":
		crawl(db, ipaddressStr, *folderurl, true)
		break
	// case "detail":
	// 	jsonData, err := json.Marshal(person) // Convert struct to JSON
	// 	if err != nil {
	// 		fmt.Println("Error:", err)
	// 		return
	// 	}
    // fmt.Println(string(jsonData))
	// 	fmt.Println(getIPAddressInfo(getDetailIpAddress(db, ipaddressStr)))
	// 	break
	case "delete":
		customutil.DeleteIpAddress(db, ipaddressStr)
	case "deleteall":
		deleteAllTable(db)
		break
	default: break;
	}
}
func crawlall(db *sql.DB, url string) {
	c := colly.NewCollector(
		colly.AllowedDomains(),
	)
	c.OnHTML("tbody", func(e *colly.HTMLElement) {
		arrUrl := []string{}
		useLocalFile := true
		startCrawl := false;
		e.ForEach("tr > td", func(_ int, kf *colly.HTMLElement) {
			urlVals := kf.ChildAttrs("a", "href")
			for _, item := range urlVals {
				if strings.Contains(item, "82.66.91.142"){ startCrawl = true; }
				fmt.Println("get url: ",startCrawl)
				if(startCrawl == false) { continue; }
				if strings.Contains(item, "file_") {
					re := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
					match := re.FindString(item)
					if match != "" {
						arrUrl = append(arrUrl, match)
					}
				}
			}
		})
		// fmt.Println("get arr url", len(arrUrl))
		for _, item := range arrUrl {
			crawl(db, item, url, useLocalFile)
		}
	})
	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting: ", r.URL.String())
	})
	c.OnResponse(func(r *colly.Response) {
		// fmt.Println("Response received!")
		fmt.Println("Status Code:", r.StatusCode)
		// fmt.Println("Response Body:", string(r.Body)) // Convert bytes to string
	})

	c.Visit(url)
}
func crawl(db *sql.DB, ipaddress string, folderurl string, islocal bool) {
	c := colly.NewCollector(
		colly.AllowedDomains(),
	)
	checkAllDataComplete := en.CheckAllValidData{
		IsPortdescValid: false,
		IsGeneralinfoValid: false,
		IsVulndescValid: false,
		IsTagdescValid: false,
		IsTechnologyValid: false,
	}
	ipinfoHolder := en.IpInfoLinkdataHolder{
		IPAddress: ipaddress,
		Tagdata: []en.TagDesc{},
		Portdata: []en.PortDesc{},
		Geninfo: []en.GeneralInfo{},
		Vulndata: []en.VulnDesc{},
		Techdata: []en.Technology{},
	}
	c.OnResponse(func(r *colly.Response) {
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(r.Body))
		if err != nil {
			log.Fatalf("Failed to parse HTML: %v", err)
		}
		if doc.Find(".card.card-yellow.card-padding > .table").Length() == 0 {
			checkAllDataComplete.IsGeneralinfoValid = true
		}
		if doc.Find("div #tags").Length() == 0 {
			checkAllDataComplete.IsTagdescValid = true
		}
		if doc.Find(".six.columns").Length() == 0 {
			checkAllDataComplete.IsPortdescValid = true
		}
		if doc.Find(".card.card-padding.card-purple").Length() == 0 {
			checkAllDataComplete.IsTechnologyValid = true
		}
		if doc.Find(".card.card-red.card-padding > .table").Length() == 0 {
			checkAllDataComplete.IsVulndescValid = true
		}
		
	})
	
	// get data for table generalinfo
	c.OnHTML(".card.card-yellow.card-padding > .table", func(e *colly.HTMLElement) {
		// listNewGenInfo := []GeneralInfo{}
		e.ForEach("tr", func(_ int, kf *colly.HTMLElement) {
			var domValue = kf.ChildTexts("td")
			var valueCheck = kf.ChildTexts("td > a")
			var title = domValue[0]
			var desc = domValue[1]
			if(len(valueCheck)>=1){
				desc = newLineArrStr(valueCheck)
			}
			// fmt.Println("test val", valueCheck)
			newGenInfo := en.GeneralInfo{
				GeneralInfoId: 0,
				Title: title,
				Value: desc,
			}
			ipinfoHolder.Geninfo = append(ipinfoHolder.Geninfo, newGenInfo) 
			// listNewGenInfo = append(listNewGenInfo, newGenInfo)
		})
		checkAllDataComplete.IsGeneralinfoValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println(ipinfoHolder.geninfo)
		// fmt.Println("check 1")
	})
	
	// get data for tagdesc table
	c.OnHTML("div #tags", func(e *colly.HTMLElement) {
		var arrayDescVal = e.ChildTexts(".tag")
		for _, tagStr := range arrayDescVal {
			ipinfoHolder.Tagdata = append(ipinfoHolder.Tagdata, en.TagDesc{
				TagId: 0,
				Title: tagStr,
			})
		}
		checkAllDataComplete.IsTagdescValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println(arrayDescVal)
		// fmt.Println("")
	})
	
	// get data for portdesc table
	c.OnHTML(".six.columns", func(e *colly.HTMLElement) {
		var arrayDescVal = e.ChildTexts(".card.card-padding.banner")
		var arrayTitle = e.ChildTexts(".card.card-light-blue.card-padding > #ports > a")
		var imagedata = e.ChildAttrs(".card.card-padding.banner > a > img", "src")
		var hrefdata = e.ChildAttrs(".card.card-padding.banner > a", "href")
		// var countU = 0
		// fmt.Println("%d and %d", len(imagedata), len(hrefdata))
		var mapImagedata map[string]string
		mapImagedata = make(map[string]string)
		for idx, value := range hrefdata {
			port := getValueUrl("p", value)
			fileName := fmt.Sprintf("%s_%s.png", ipaddress, port)
			printImageBase64(ipaddress, fileName, imagedata[idx])
			imageURL := fmt.Sprintf("<img src=\"../image/%s/%s\" style=\"width: 100%s; height: 420px\" />", ipaddress, fileName, "%%")
			mapImagedata[port] = imageURL
			// fmt.Println("get value %s", )
		}
		var idx = 0
		for _, port := range arrayTitle {
			// if(countU>0) { break; }
			var searchDOM = fmt.Sprintf("#%s", port)
			var elementWithID = e.DOM.Find(searchDOM)
			if elementWithID.Length() > 0 {
				// var getLink = e.ChildAttrs(fmt.Sprintf("%s > div > .link", searchDOM), "href")
				var portTitle = elementWithID.Text()
				
				var portDesc = arrayDescVal[idx]
				value, isExist := mapImagedata[port]
				if(isExist){
					portDesc+=value
				}
				ipinfoHolder.Portdata = append(ipinfoHolder.Portdata, en.PortDesc{
					SpecificPortId: 0,
					Title: portParse(portTitle),
					Value: portDesc,
				})
				idx+=1
				// fmt.Println(elementWithID.Text())
			}
			// fmt.Println(arrayDescVal[idx])
			// countU+=1;
		}
		checkAllDataComplete.IsPortdescValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println("")
		// fmt.Println(fmt.Sprintf("%d check %d", len(arrayDescVal), len(arrayTitle)))
	})

	// get data for technology table
	c.OnHTML(".card.card-padding.card-purple", func(e *colly.HTMLElement) {
		e.ForEach(".category", func(_ int, kf *colly.HTMLElement) {
			var titleTech = kf.ChildText(".category-heading")
			var listTechUsed = kf.ChildText(".technology")//it have to used kf.ChildTexts(".technology")
			ipinfoHolder.Techdata = append(ipinfoHolder.Techdata, en.Technology{
				TechId: 0,
				Title: titleTech,
				Value: listTechUsed,
			})
			// fmt.Println("")
		})
		// fmt.Println("check 2")
		checkAllDataComplete.IsTechnologyValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
	})
	
	// get data for vulndesc table
	c.OnHTML(".card.card-red.card-padding > .table", func(e *colly.HTMLElement) {
		// var countCheck = 0
		e.ForEach("tr", func(_ int, kf *colly.HTMLElement) {
			// if(countCheck > 0){ return; }
			// countCheck+=1;
			var valueDom = kf.ChildTexts("td")
			// fmt.Println(valueDom)
			var titleVuln = valueDom[0]
			var descVuln = valueDom[1]
			ipinfoHolder.Vulndata = append(ipinfoHolder.Vulndata, en.VulnDesc{
				VulnId: 0,
				Title: titleVuln,
				Value: descVuln,
			})
			
		})
		// fmt.Println("check 1")
		checkAllDataComplete.IsVulndescValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
	})
	
	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting: ", r.URL.String())
	})
	c.OnResponse(func(r *colly.Response) {
		fmt.Println("Response received!")
		fmt.Println("Status Code:", r.StatusCode)
	})
	c.OnError(func(r *colly.Response, err error) {
		log.Println("Request failed:", err)
	})
	startUrl := ""
	if (islocal) {
		startUrl = fmt.Sprintf("%sfile_%s.html", folderurl, ipaddress) 
	}else{
		startUrl = fmt.Sprintf("%s%s", folderurl, ipaddress) 
	}
	fmt.Println(startUrl)
	c.Visit(startUrl)
}
func checkAllComplete(db *sql.DB, ipaddress string, checkData en.CheckAllValidData, ipinfoHolder en.IpInfoLinkdataHolder) (bool) {
	if (checkData.IsValid()){
		insertAllData(db, ipaddress, ipinfoHolder.Tagdata, ipinfoHolder.Portdata, ipinfoHolder.Geninfo, ipinfoHolder.Vulndata, ipinfoHolder.Techdata)
	}
	return false
}
func deleteAllTable(db *sql.DB) (bool) {
	isDeleteError1, _, _ := getSQLData(db, "DROP TABLE `ipinfolink`;")
	isDeleteError2, _, _ := getSQLData(db, "DROP TABLE `portdesc`;")
	isDeleteError3, _, _ := getSQLData(db, "DROP TABLE `generalinfo`;")
	isDeleteError4, _, _ := getSQLData(db, "DROP TABLE `vulndesc`;")
	isDeleteError5, _, _ := getSQLData(db, "DROP TABLE `tagdesc`;")
	isDeleteError6, _, _ := getSQLData(db, "DROP TABLE `technology`;")
	isDeleteError7, _, _ := getSQLData(db, "DROP TABLE `listgeneralinfo`;")
	isDeleteError8, _, _ := getSQLData(db, "DROP TABLE `listtag`;")
	isDeleteError9, _, _ := getSQLData(db, "DROP TABLE `listvuln`;")
	isDeleteError10, _, _ := getSQLData(db, "DROP TABLE `listtech`;")
	isDeleteError11, _, _ := getSQLData(db, "DROP TABLE `listport`;")
	return isDeleteError1 || isDeleteError2 || isDeleteError3 || isDeleteError4 || isDeleteError5 || isDeleteError6 || isDeleteError7 || isDeleteError8 || isDeleteError9 || isDeleteError10 || isDeleteError11
}
func insertAllData(db *sql.DB, ipaddress string, tagdata []en.TagDesc, portdata []en.PortDesc, geninfo []en.GeneralInfo, vulndata []en.VulnDesc, techdata []en.Technology) (bool) {
	// fmt.Println("is check 0")
	listGeneralInfoId := getLastIndexTable(db, "listgeneralinfo", "listgeneralinfoid")
	// create random id for ListGeneralInfoId
	// if isIpAddressValid(db, 0, ipaddress) { return false }
	for _, item := range geninfo {
		var isValid = false
		var geninfoid int64 = 0
		idCheck, isIpValueCanInsertInTable := checkListValid(db, 0, ipaddress, item.Title)
		if isIpValueCanInsertInTable {
			geninfoid, isValid = insertGeneralInfo(db, item.Title, item.Value)
		}else{
			_, _ = updateGeneralInfo(db, idCheck, item.Title, item.Value)
		}
		if(isValid){
			insertListGenInfo(db, listGeneralInfoId, ipaddress, geninfoid)
			updateLastIndex(db, "listgeneralinfo", listGeneralInfoId)
		}
	}
	listtagid := getLastIndexTable(db, "listtag", "listtagid")
	for _, item := range tagdata {
		var isValid = false
		var tagid int64 = 0
		idCheck, isIpValueCanInsertInTable := checkListValid(db, 2, ipaddress, item.Title)
		if isIpValueCanInsertInTable {
			tagid, isValid = insertTagData(db, item.Title)
		}else{
			updateTagData(db, idCheck, item.Title)
		}
		if(isValid){
			insertListTag(db, listtagid, ipaddress, tagid)
			updateLastIndex(db, "listtag", listtagid)
		}
	}
	listportid := getLastIndexTable(db, "listport", "listportid")
	for _, item := range portdata {
		var isValid = false
		var portid int64 = 0
		idCheck, isIpValueCanInsertInTable := checkListValid(db, 3, ipaddress, item.Title)
		if isIpValueCanInsertInTable {
			portid, isValid = insertPortDesc(db, item.Title, item.Value)
		}else{
			updatePortDesc(db, idCheck, item.Title, item.Value)
		}
		if(isValid){
			insertListPort(db, listportid, ipaddress, portid)
			updateLastIndex(db, "listport", listportid)
		}
	}
	listvulnid := getLastIndexTable(db, "listvuln", "listvulnid")
	for _, item := range vulndata {
		var isValid = false
		var vulnid int64 = 0
		idCheck, isIpValueCanInsertInTable := checkListValid(db, 1, ipaddress, item.Title)
		if isIpValueCanInsertInTable {
			vulnid, isValid = insertVulnDesc(db, item.Title, item.Value)
		}else{
			updateVulnDesc(db, idCheck, item.Title, item.Value)
		}
		if(isValid){
			insertListVuln(db, listvulnid, ipaddress, vulnid)
			updateLastIndex(db, "listvuln", listvulnid)
		}
	}
	listtechid := getLastIndexTable(db, "listtech", "listtechid")
	for _, item := range techdata {
		var isValid = false
		var techid int64 = 0
		idCheck, isIpValueCanInsertInTable := checkListValid(db, 4, ipaddress, item.Title)
		if isIpValueCanInsertInTable {
			techid, isValid = insertTechData(db, item.Title, item.Value)
		}else{
			updateTechData(db, idCheck, item.Title, item.Value)
		}
		if(isValid){
			insertListTech(db, listtechid, ipaddress, techid)
			updateLastIndex(db, "listtech", listtechid)
		}
	}
	return insertIPInfo(db, ipaddress, listtagid, listGeneralInfoId, listvulnid, listtechid, listportid)
}
func insertIPInfo(db *sql.DB, ipaddress string, listtagid int64, listgeneralinfoid int64, listvulnid int64, listtechid int64, listportid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `ipinfolink`(`ipaddress`, `listtagid`, `listgeneralinfoid`, `listvulnid`, `listtechid`, `listportid`) VALUES ('%s', '%d','%d','%d','%d','%d')", ipaddress, listtagid, listgeneralinfoid, listvulnid, listtechid, listportid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertPortDesc(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `portdesc`(`title`, `value`) VALUES ('%s', ?)", title)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{value})
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func updatePortDesc(db *sql.DB, idCheck int64, title string, value string) (int64, bool) {
	var UpdateSQLStr = fmt.Sprintf("UPDATE `portdesc` SET `title` = '%s', `value` = '%s' WHERE `specificportid` = %d", title, value, idCheck)
	var returnId int64 = 0
	isUpdateError, returnId, _, _ := getSQLResultid(db, UpdateSQLStr, []string{})
	if(!isUpdateError){
		return returnId, true
	}
	return -1, false
}
func checkListValid(db *sql.DB, id int32, ipAddress string, title string) (int64, bool) {
	tableName := func(id int32) string {
		switch(id){
			case 0: return `generalinfo`
			case 1: return `vulndesc`
			case 2: return `tagdesc`
			case 3: return `portdesc`
			case 4: return `technology`
			// case 0: return `ipinfolink`
		default: return ""
		}
	}(id)
	tableListName := func(id int32) string {
		switch(id){
		case 0: return "listgeneralinfo"
		case 1: return "listvuln"
		case 2: return "listtag"
		case 3: return "listport"
		case 4: return "listtech"
		default: return ""
		}
	}(id)
	idName := func(id int32) string {
		switch(id){
		case 0: return "generalinfoId"
		case 1: return "vulnid"
		case 2: return "tagid"
		case 3: return "specificportid"
		case 4: return "techid"
		default: return ""
		}
	}(id)
	if(tableName == ""){ return 0, false }
	selectCheckIp := fmt.Sprintf("SELECT COUNT(*), g.%s FROM `%s` l INNER JOIN `%s` g ON l.`%s` = g.`%s` WHERE l.ipaddress", idName, tableListName, tableName, idName, idName)
	selectCheckIp = fmt.Sprintf("%s like '%%%s%%' and g.title like '%%%s%%';", selectCheckIp, ipAddress, title)
	// fmt.Println("running check")
	// fmt.Println(selectCheckIp)
	isselectError, selectRes, _ := getSQLData(db, selectCheckIp)
	if(!isselectError){
		var countvalue = 0
		var idCheck *int64
		defer selectRes.Close()
		selectRes.Next()
		err := selectRes.Scan(&countvalue, &idCheck)
		if err != nil {
			log.Fatal(err)
		}
		returnId := func(idRet *int64) int64 {
			if(idRet == nil){
				return 0
			}else{
				return *idRet
			}
		}(idCheck)
		return returnId, countvalue==0
	}
	return 0, false
}
func insertGeneralInfo(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `generalinfo`(`title`, `value`) VALUES ('%s','%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{})
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func updateGeneralInfo(db *sql.DB, idCheck int64, title string, value string) (int64, bool) {
	var UpdateSQLStr = fmt.Sprintf("UPDATE `generalinfo` SET `title` = '%s', `value` = '%s' WHERE `generalinfoId` = %d", title, value, idCheck)
	// fmt.Println(UpdateSQLStr)
	var returnId int64 = 0
	isUpdateError, returnId, _, _ := getSQLResultid(db, UpdateSQLStr, []string{})
	if(!isUpdateError){
		return returnId, true
	}
	return -1, false
}

func insertVulnDesc(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `vulndesc`(`title`, `value`) VALUES ('%s', ?)", title)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{value})
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func updateVulnDesc(db *sql.DB, idCheck int64, title string, value string) (int64, bool) {
	var UpdateSQLStr = fmt.Sprintf("UPDATE `vulndesc` SET `title` = '%s', `value` = '%s' WHERE `vulnid` = %d", title, value, idCheck)
	var returnId int64 = 0
	isUpdateError, returnId, _, _ := getSQLResultid(db, UpdateSQLStr, []string{})
	if(!isUpdateError){
		return returnId, true
	}
	return -1, false
}
func insertTagData(db *sql.DB, title string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `tagdesc`(`title`) VALUES ('%s')", title)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{})
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func updateTagData(db *sql.DB, idCheck int64, title string) (int64, bool) {
	var UpdateSQLStr = fmt.Sprintf("UPDATE `tagdesc` SET `title` = '%s' WHERE `tagid` = %d", title,  idCheck)
	var returnId int64 = 0
	isUpdateError, returnId, _, _ := getSQLResultid(db, UpdateSQLStr, []string{})
	if(!isUpdateError){
		return returnId, true
	}
	return -1, false
}

func insertTechData(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `technology`(`title`, `value`) VALUES ('%s', '%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{})
	if(!isInsertError){
		return returnId, true
	}
	return -1, false
}
func updateTechData(db *sql.DB, idCheck int64, title string, value string) (int64, bool) {
	var UpdateSQLStr = fmt.Sprintf("UPDATE `technology` SET `title` = '%s', `value` = '%s' WHERE `techid` = %d", title, value, idCheck)
	var returnId int64 = 0
	isUpdateError, returnId, _, _ := getSQLResultid(db, UpdateSQLStr, []string{})
	if(!isUpdateError){
		return returnId, true
	}
	return -1, false
}
func insertListGenInfo(db *sql.DB, listgeneralinfoid int64, ipaddress string, generalinfoid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listgeneralinfo`(`listgeneralinfoid`, `ipaddress`, `generalinfoid`) VALUES ('%d','%s','%d')", listgeneralinfoid, ipaddress, generalinfoid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListTag(db *sql.DB, listtagid int64, ipaddress string, tagid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listtag`(`listtagid`, `ipaddress`, `tagid`) VALUES ('%d','%s','%d')", listtagid, ipaddress, tagid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListVuln(db *sql.DB, listvulnid int64, ipaddress string, vulnid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listvuln`(`listvulnid`, `ipaddress`, `vulnid`) VALUES ('%d','%s', '%d')", listvulnid, ipaddress, vulnid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListTech(db *sql.DB, listtechid int64, ipaddress string, techid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listtech`(`listtechid`, `ipaddress`, `techid`) VALUES ('%d', '%s', '%d')", listtechid, ipaddress, techid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func insertListPort(db *sql.DB, listportid int64, ipaddress string, specificportid int64) (bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `listport`(`listportid`, `ipaddress`, `specificportid`) VALUES ('%d', '%s', '%d')", listportid, ipaddress, specificportid)
	isInsertError, insertRes, _ := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	return false
}
func isIpAddressValid(db *sql.DB, id int32, ip string) bool {
	tableName := func(id int32) string {
		switch(id){
		case 0: return "listgeneralinfo"
		case 1: return "listvuln"
		case 2: return "listtag"
		case 3: return "listport"
		case 4: return "listtech"
		default: return ""
		}
	}(id)
	if(tableName == ""){ return false }
	var checkIPSQLStr = fmt.Sprintf("SELECT COUNT(*) FROM `%s` WHERE `ipaddress` like '%s';", tableName, ip)
	ischeckIPError, checkIPRes, _ := getSQLData(db, checkIPSQLStr)
	if(!ischeckIPError){
		var countvalue = 0
		defer checkIPRes.Close()
		checkIPRes.Next()
		err := checkIPRes.Scan(&countvalue)
		if err != nil {
			log.Fatal(err)
		}
		// fmt.Println("get check count", countvalue)
		return countvalue==0
	}
	return false
}
func checkAllTable(db *sql.DB, dbName string) (bool) {
	var checkPortListVal = checkListPort(db,dbName) 
	var checkTechListVal = checkListTech(db, dbName) 
	var checkVulnListVal = checkListVuln(db, dbName) 
	var checkTagListVal = checkListTag(db, dbName) 
	var checkGenInfoListVal = checkListGeneralInfo(db, dbName)
	var checkLastIndex = checkUpdaterIndex(db, dbName)
	var checkListTable = checkLastIndex && checkPortListVal && checkTechListVal && checkVulnListVal && checkTagListVal && checkGenInfoListVal
	var checkTechnologyVal = checkTechnology(db, dbName)
	var checkTagDescVal = checkTagDesc(db, dbName)
	var checkVulnVal = checkVuln(db, dbName)
	var checkGeneralInfoVal = checkGeneralInfo(db, dbName)
	var checkPortVal = checkPort(db, dbName)
	var checkDataHolderTable = checkTechnologyVal && checkTagDescVal && checkVulnVal && checkGeneralInfoVal && checkPortVal
	var checkMainTable = checkIPInfoLink(db, dbName)
	return checkListTable && checkDataHolderTable && checkMainTable
}
func getSQLData(db *sql.DB,query string) (bool, *sql.Rows, error) {
	res, err := db.Query(query)
	var isError bool = false
    if err != nil {
        isError = true
    }
	return isError,res,err
}
func getSQLResultid(db *sql.DB, query string, value []string) (bool, int64, sql.Result, error) {
	result, err := db.Exec(query, interfaceSlice(value)...)
	var isError bool = false
	var lastInsertID int64 = 0
	if err != nil {
		isError = true
	}else{
		lastInsertID, err = result.LastInsertId()
		if err != nil {
			isError = true
		}
	}
	return isError, lastInsertID, result, err
}

// create main table
func checkIPInfoLink(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "ipinfolink")){
		var createSQL = `CREATE TABLE ipinfolink (
			id INT(20) NOT NULL AUTO_INCREMENT,
			ipaddress VARCHAR(255) NOT NULL,
			listtagid INT(20) NOT NULL,
			listgeneralinfoid INT(20) NOT NULL,
			listvulnid INT(20) NOT NULL,
			listtechid INT(20) NOT NULL,
			listportid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
// create table info item
func checkPort(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "portdesc")){
		var createSQL = `CREATE TABLE portdesc (
			specificportid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (specificportid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, err := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}else{
			fmt.Println(err)
		}
	}
	return false
}
func checkGeneralInfo(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "generalinfo")){
		var createSQL = `CREATE TABLE generalinfo (
			generalinfoId INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(255) NOT NULL,
			PRIMARY KEY (generalinfoId)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkUpdaterIndex(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "lastindextable")){
		var createSQL = `CREATE TABLE lastindextable (
			id INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func updateLastIndex(db *sql.DB, tableName string, value int64) (bool) {
	var updateSQL = fmt.Sprintf("UPDATE `lastindextable` SET `value` = '%s' where `%s` like %s", tableName,value) 
	isUpdateError, updateRes, _ := getSQLData(db, updateSQL)
	if(!isUpdateError){
		defer updateRes.Close()
		return false
	}
	return true
}
func checkVuln(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "vulndesc")){
		var createSQL = `CREATE TABLE vulndesc (
			vulnid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (vulnid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkTagDesc(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "tagdesc")){
		var createSQL = `CREATE TABLE tagdesc (
			tagid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			PRIMARY KEY (tagid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkTechnology(db *sql.DB, dbName string) (bool){
	if(!checkTable(db, dbName, "technology")){
		var createSQL = `CREATE TABLE technology (
			techid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(255) NOT NULL,
			PRIMARY KEY (techid)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
// create table list
func checkListGeneralInfo(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listgeneralinfo")){
		var createSQL = `CREATE TABLE listgeneralinfo (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listgeneralinfoid VARCHAR(255) NOT NULL,
			ipaddress VARCHAR(255) NOT NULL,
			generalinfoid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListTag(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listtag")){
		var createSQL = `CREATE TABLE listtag (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listtagid INT(20) NOT NULL,
			ipaddress VARCHAR(255) NOT NULL,
			tagid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListVuln(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listvuln")){
		var createSQL = `CREATE TABLE listvuln (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listvulnid INT(20) NOT NULL,
			ipaddress VARCHAR(255) NOT NULL,
			vulnid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListTech(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listtech")){
		var createSQL = `CREATE TABLE listtech (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listtechid INT(20) NOT NULL,
			ipaddress VARCHAR(255) NOT NULL,
			techid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkListPort(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "listport")){
		var createSQL = `CREATE TABLE listport (
			id INT(20) NOT NULL AUTO_INCREMENT,
			listportid INT(20) NOT NULL,
			ipaddress VARCHAR(255) NOT NULL,
			specificportid INT(20) NOT NULL,
			PRIMARY KEY (id)
		) ENGINE=InnoDB DEFAULT CHARSET=latin1;`
		isInsertError, insertRes, _ := getSQLData(db, createSQL)
		if(!isInsertError){
			defer insertRes.Close()
			return true
		}
	}
	return false
}
func checkTable(db *sql.DB, dbName string, tableName string) (bool) {
	var count int = 0
	var checktableStr = fmt.Sprintf(`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = "%s" AND table_name = "%s";`, dbName, tableName)
	isCheckTableError, CheckTableRes, err := getSQLData(db, checktableStr)
	if err != nil {
		fmt.Println(err)
	}
	if(!isCheckTableError){
		defer CheckTableRes.Close()
		CheckTableRes.Next()
		err := CheckTableRes.Scan(&count)
		if err != nil {
			log.Fatal(err)
		}
		return (count > 0)
	}
	return false
}
// GenerateRandomID creates a random integer ID
func GenerateRandomID() int64 {
	rand.Seed(time.Now().UnixNano())
	return rand.Int63n(1000000) // Generate a random number in a defined range
}
func getLastIndexTable(db *sql.DB, tableName, columnName string) int64 {
	var selectLast = fmt.Sprintf("SELECT `value` FROM `lastindextable` WHERE `title` like '%s'", tableName)
	isSelectLastError, selectLastRes, _ := getSQLData(db, selectLast)
	var lastIndex = 0
	if(!isSelectLastError){
		defer selectLastRes.Close()
		selectLastRes.Next()
		err := selectLastRes.Scan(&lastIndex)
		// if err != nil { log.Fatal(err) }
		// return lastIndex
	}
	return lastIndex
}

// CreateUniqueRandomID generates a random ID and ensures it's unique in the database
func CreateUniqueRandomID(db *sql.DB, tableName, columnName string) (int64, error) {
	for {
		randomID := GenerateRandomID()
		query := fmt.Sprintf("SELECT COUNT(*) FROM `%s` WHERE `%s` = ?", tableName, columnName)
		var count int
		err := db.QueryRow(query, randomID).Scan(&count)
		if err != nil {
			return 0, fmt.Errorf("failed to check ID existence: %w", err)
		}
		if count == 0 {
			return randomID, nil
		}
	}
}


func getPrefix(s string, length int) string {
	if length > len(s) { // Ensure length does not exceed string length
		length = len(s)
	}
	return s[:length]
}
func interfaceSlice(slice []string) []interface{} {
	args := make([]interface{}, len(slice))
	for i, v := range slice {
		args[i] = v
	}
	return args
}
func jsonArrStr(arrStr []string) string {
	jsonData, err := json.Marshal(arrStr)
	if err != nil {
		return "[]"
	}
	return string(jsonData)
}
func newLineArrStr(arrStr []string) string {
	var newLinStr = ""
	for _, item := range arrStr {
		newLinStr+=(item+"\n")
	}
	return newLinStr
}
func printImageBase64(ipaddress string, filename string, str string){
	parts := strings.Split(str, ",")
	if len(parts) != 2 {
		fmt.Println("Invalid base64 image data")
		return
	}
	base64String := parts[1]
	imageData, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return
	}
	outputFile := fmt.Sprintf("image/%s/%s", ipaddress, filename)
	folderCheck := fmt.Sprintf("image/%s/", ipaddress)
	if err := checkAndCreateFolder(folderCheck); err != nil {
		fmt.Println("Error:", err)
		return
	}
	err = ioutil.WriteFile(outputFile, imageData, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
}
func getValueUrl(attr string, rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	queryParams := parsedURL.Query()
	return queryParams.Get(attr)
}
func checkAndCreateFolder(folderPath string) error {
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		err := os.MkdirAll(folderPath, os.ModePerm) // Creates parent directories if needed
		if err != nil {
			return fmt.Errorf("failed to create folder: %v", err)
		}
		fmt.Println("Folder created successfully:", folderPath)
	} else {
		fmt.Println("Folder already exists:", folderPath)
	}
	return nil
}
func portParse(str string) string {
	splitStr := strings.Split(str, "/")
	parseCheck := strings.Fields(splitStr[0]) // Splits by spaces and removes empty entries
	if len(parseCheck) == 0 || len(splitStr) < 2 {
		return "" // Handle edge cases
	}
	return parseCheck[len(parseCheck)-1] + " " + splitStr[1]
}
