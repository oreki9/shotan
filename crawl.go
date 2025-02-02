package main

import (
	// "encoding/json"
	"flag"
	"fmt"
	"github.com/gocolly/colly"
	"log"
	"math/rand"
	"time"
	"encoding/json"
	// "strings"

	"database/sql"
    _ "github.com/go-sql-driver/mysql"
)

type IpInfoLink struct {
	Id int
	IPAddress string
	ListTagId string
	ListGeneralInfoId string
	ListVulnId string
	ListTechId string
	ListPortId string
}
type IpInfoLinkdataHolder struct {
	IPAddress string
	tagdata []TagDesc
	portdata []PortDesc
	geninfo []GeneralInfo
	vulndata []VulnDesc
	techdata []Technology
}
type CheckAllValidData struct {
	isPortdescValid bool
	isGeneralinfoValid bool
	isVulndescValid bool
	isTagdescValid bool
	isTechnologyValid bool
}
func (d CheckAllValidData) isValid() bool {
	return d.isPortdescValid && d.isGeneralinfoValid && d.isVulndescValid && d.isTagdescValid && d.isTechnologyValid
}
type ListPort struct {
	Id int
	ListPortId int
	IPAddress string
	SpecificPortId int
}
type ListTech struct {
	Id int
	ListTechId int
	IPAddress string
	TechId int
}
type ListVuln struct {
	Id int
	ListVulnId int
	IPAddress string
	VulnId int
}
type ListTag struct {
	Id int
	ListTagId int
	IPAddress string
	TagId int
}
type ListGeneralInfo struct {
	id int
	ListGeneralInfoId int
	IPAddress string
	GeneralInfoId int
}
type TagDesc struct {
	TagId int
	Title string
}
type PortDesc struct {
	SpecificPortId int// even title is same but value desc is not same
	Title string
	Value string
}
type GeneralInfo struct {
	GeneralInfoId int
	Title string
	Value string
}
type VulnDesc struct {
	VulnId int
	Title string
	Value string
}
type Technology struct {
	TechId int
	Title string
	Value string
}
func main() {
	ipaddress := flag.String("ipaddress", "109.206.245.168", "ip address target")
	mode := flag.String("mode", "detail", "ip address target")
	//mode: fetch, detail, delete
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
	case "fetch":
		crawl(db, ipaddressStr)
		break
	case "detail":
		fmt.Println(getIPAddressInfo(getDetailIpAddress(db, ipaddressStr)))
		break
	case "delete":
		deleteAllTable(db)
		break
	default: break;
	}
}

func crawl(db *sql.DB, ipaddress string) {
	c := colly.NewCollector(
		colly.AllowedDomains(),
	)
	checkAllDataComplete := CheckAllValidData{
		isPortdescValid: false,
		isGeneralinfoValid: false,
		isVulndescValid: false,
		isTagdescValid: false,
		isTechnologyValid: false,
	}
	ipinfoHolder := IpInfoLinkdataHolder{
		IPAddress: ipaddress,
		tagdata: []TagDesc{},
		portdata: []PortDesc{},
		geninfo: []GeneralInfo{},
		vulndata: []VulnDesc{},
		techdata: []Technology{},
	}
	// get data for table generalinfo
	c.OnHTML(".card.card-yellow.card-padding > .table", func(e *colly.HTMLElement) {
		// listNewGenInfo := []GeneralInfo{}
		e.ForEach("tr", func(_ int, kf *colly.HTMLElement) {
			var domValue = kf.ChildTexts("td")
			var title = domValue[0]
			var desc = domValue[1]
			newGenInfo := GeneralInfo{
				GeneralInfoId: 0,
				Title: title,
				Value: desc,
			}
			ipinfoHolder.geninfo = append(ipinfoHolder.geninfo, newGenInfo) 
			// listNewGenInfo = append(listNewGenInfo, newGenInfo)
		})
		checkAllDataComplete.isGeneralinfoValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println(ipinfoHolder.geninfo)
		// fmt.Println("check 1")
	})
	
	// get data for tagdesc table
	c.OnHTML("div #tags", func(e *colly.HTMLElement) {
		var arrayDescVal = e.ChildTexts(".tag")
		for _, tagStr := range arrayDescVal {
			ipinfoHolder.tagdata = append(ipinfoHolder.tagdata, TagDesc{
				TagId: 0,
				Title: tagStr,
			})
		}
		checkAllDataComplete.isTagdescValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println(arrayDescVal)
		// fmt.Println("")
	})
	
	// get data for portdesc table
	c.OnHTML(".six.columns", func(e *colly.HTMLElement) {
		var arrayDescVal = e.ChildTexts(".card.card-padding.banner")
		var arrayTitle = e.ChildTexts(".card.card-light-blue.card-padding > #ports > a")
		// var countU = 0
		for idx, value := range arrayTitle {
			// if(countU>0) { break; }
			var searchDOM = fmt.Sprintf("#%s > span", value)
			var elementWithID = e.DOM.Find(searchDOM)
			if elementWithID.Length() > 0 {
				var portTitle = elementWithID.Text()
				var portDesc = arrayDescVal[idx]
				ipinfoHolder.portdata = append(ipinfoHolder.portdata, PortDesc{
					SpecificPortId: 0,
					Title: portTitle,
					Value: portDesc,
				})
				// fmt.Println(elementWithID.Text())
			}
			// fmt.Println(arrayDescVal[idx])
			// countU+=1;
		}
		checkAllDataComplete.isPortdescValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println("")
		// fmt.Println(fmt.Sprintf("%d check %d", len(arrayDescVal), len(arrayTitle)))
	})

	// get data for technology table
	c.OnHTML(".card.card-padding.card-purple", func(e *colly.HTMLElement) {
		e.ForEach(".category", func(_ int, kf *colly.HTMLElement) {
			var titleTech = kf.ChildText(".category-heading")
			var listTechUsed = kf.ChildText(".technology")//it have to used kf.ChildTexts(".technology")
			ipinfoHolder.techdata = append(ipinfoHolder.techdata, Technology{
				TechId: 0,
				Title: titleTech,
				Value: listTechUsed,
			})
			// fmt.Println("")
		})
		checkAllDataComplete.isTechnologyValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
		// fmt.Println("check 2")
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
			ipinfoHolder.vulndata = append(ipinfoHolder.vulndata, VulnDesc{
				VulnId: 0,
				Title: titleVuln,
				Value: descVuln,
			})
			
		})
		// fmt.Println("check 1")
		checkAllDataComplete.isVulndescValid = true
		checkAllComplete(db, ipaddress, checkAllDataComplete, ipinfoHolder)
	})
	
	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting: ", r.URL.String())
	})

	// uncomment below line if you enable Async mode
	// c.Wait()
	startUrl := fmt.Sprintf("http://localhost/shotan/file_%s.html", ipaddress)
	print("start")
	c.Visit(startUrl)
}
func checkAllComplete(db *sql.DB, ipaddress string, checkData CheckAllValidData, ipinfoHolder IpInfoLinkdataHolder) (bool) {
	if (checkData.isValid()){
		insertAllData(db, ipaddress, ipinfoHolder.tagdata, ipinfoHolder.portdata, ipinfoHolder.geninfo, ipinfoHolder.vulndata, ipinfoHolder.techdata)
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
func insertAllData(db *sql.DB, ipaddress string, tagdata []TagDesc, portdata []PortDesc, geninfo []GeneralInfo, vulndata []VulnDesc, techdata []Technology) (bool) {
	listGeneralInfoId, _ := CreateUniqueRandomID(db, "generalinfo", "listgeneralinfoid")
	// create random id for ListGeneralInfoId
	for _, item := range geninfo {
		geninfoid, isValid := insertGeneralInfo(db, item.Title, item.Value)
		if(isValid){
			insertListGenInfo(db, listGeneralInfoId, ipaddress, geninfoid)
		}
	}
	listtagid, _ := CreateUniqueRandomID(db, "listtag", "listtagid")
	for _, item := range tagdata {
		tagid, isValid := insertTagData(db, item.Title)
		if(isValid){
			insertListTag(db, listtagid, ipaddress, tagid)
		}
	}
	listportid, _ := CreateUniqueRandomID(db, "listport", "listportid")
	for _, item := range portdata {
		portid, isValid := insertPortDesc(db, item.Title, item.Value)
		if(isValid){
			insertListPort(db, listportid, ipaddress, portid)
		}
	}
	listvulnid, _ := CreateUniqueRandomID(db, "listvuln", "listvulnid")
	for _, item := range vulndata {
		vulnid, isValid := insertVulnDesc(db, item.Title, item.Value)
		if(isValid){
			insertListVuln(db, listvulnid, ipaddress, vulnid)
		}
	}
	listtechid, _ := CreateUniqueRandomID(db, "listtech", "listtechid")
	for _, item := range techdata {
		techid, isValid := insertTechData(db, item.Title, item.Value)
		if(isValid){
			insertListTech(db, listtechid, ipaddress, techid)
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
func insertGeneralInfo(db *sql.DB, title string, value string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `generalinfo`(`title`, `value`) VALUES ('%s','%s')", title, value)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{})
	if(!isInsertError){
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
func insertTagData(db *sql.DB, title string) (int64, bool) {
	var insertSQLStr = fmt.Sprintf("INSERT INTO `tagdesc`(`title`) VALUES ('%s')", title)
	var returnId int64 = 0
	isInsertError, returnId, _, _ := getSQLResultid(db, insertSQLStr, []string{})
	if(!isInsertError){
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
	isInsertError, insertRes, errCheck := getSQLData(db, insertSQLStr)
	if(!isInsertError){
		defer insertRes.Close()
		return true
	}
	print("---")
	print(errCheck)
	print("---")
	return false
}
func checkAllTable(db *sql.DB, dbName string) (bool) {
	var checkPortListVal = checkListPort(db,dbName) 
	var checkTechListVal = checkListTech(db, dbName) 
	var checkVulnListVal = checkListVuln(db, dbName) 
	var checkTagListVal = checkListTag(db, dbName) 
	var checkGenInfoListVal = checkListGeneralInfo(db, dbName)
	var checkListTable = checkPortListVal && checkTechListVal && checkVulnListVal && checkTagListVal && checkGenInfoListVal
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
	if err != nil {
		isError = true
	}
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		isError = true
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
			value VARCHAR(7000) NOT NULL,
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
func checkVuln(db *sql.DB, dbName string) (bool) {
	if(!checkTable(db, dbName, "vulndesc")){
		var createSQL = `CREATE TABLE vulndesc (
			vulnid INT(20) NOT NULL AUTO_INCREMENT,
			title VARCHAR(255) NOT NULL,
			value VARCHAR(7000) NOT NULL,
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

func getDetailIpAddress(db *sql.DB, ipaddress string) IpInfoLinkdataHolder {
	returnSqlCommand := [][]string {
		{"`generalinfoid`", "`listgeneralinfo`"},
		{"`tagid`", "`listtag`"},
		{"`vulnid`", "`listvuln`"},
		{"`techid`", "`listtech`"},
		{"`specificportid`", "`listport`"},
	}// return column name and table name
	ipinfoHolder := IpInfoLinkdataHolder{
		IPAddress: ipaddress,
		tagdata: []TagDesc{},
		portdata: []PortDesc{},
		geninfo: []GeneralInfo{},
		vulndata: []VulnDesc{},
		techdata: []Technology{},
	}
	for idx, arrVal := range returnSqlCommand {
		var selectGenInfo = fmt.Sprintf("SELECT %s FROM %s WHERE 1", arrVal[0], arrVal[1])
		isSelectError, SelectRes, _ := getSQLData(db, selectGenInfo)
		if(!isSelectError){
			defer SelectRes.Close()
			for SelectRes.Next() {
				idSelect := 0
				err := SelectRes.Scan(&idSelect)
				if err != nil { log.Fatal(err) }
				// fmt.Println("get id selec", idSelect)
				getBasicData(db, &ipinfoHolder, idx, idSelect)
			}
		}
	}
	return ipinfoHolder
	// var selectGenInfo = fmt.Sprintf("SELECT %s FROM %s WHERE 1", listColumnStr, tablename)
	// isSelectError, SelectRes, _ := getSQLData(db, selectGenInfo)
	// if(!isSelectError){
	// 	defer SelectRes.Close()
	// 	return true
	// }
}
func getBasicData(db *sql.DB, data *IpInfoLinkdataHolder, basedataIdx int, id int) {
	returnSqlCommand := [][]string {
		{"`generalinfoId`, `title`, `value`", "`generalinfo`", "`generalinfoId`"},
		{"`tagid`, `title`", "`tagdesc`", "`tagid`"},
		{"`vulnid`, `title`, `value`", "`vulndesc`", "`vulnid`"},
		{"`techid`, `title`, `value`", "`technology`", "`techid`"},
		{"`specificportid`, `title`, `value`", "`portdesc`", "`specificportid`"},
	}// return column name and table name
	var selectGenInfo = fmt.Sprintf("SELECT %s FROM %s WHERE %s = %d", returnSqlCommand[basedataIdx][0], returnSqlCommand[basedataIdx][1], returnSqlCommand[basedataIdx][2], id)
	isSelectError, SelectRes, _ := getSQLData(db, selectGenInfo)
	// fmt.Println(selectGenInfo)
	if(!isSelectError){
		defer SelectRes.Close()
		for SelectRes.Next() {
			switch(basedataIdx){
			case 0:
				var dataItem GeneralInfo
				err := SelectRes.Scan(&dataItem.GeneralInfoId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.geninfo = append(data.geninfo, dataItem)
			case 1:
				var dataItem TagDesc
				err := SelectRes.Scan(&dataItem.TagId, &dataItem.Title)
				if err != nil { log.Fatal(err) }
				data.tagdata = append(data.tagdata, dataItem)
			case 2:
				var dataItem VulnDesc
				err := SelectRes.Scan(&dataItem.VulnId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.vulndata = append(data.vulndata, dataItem)
			case 3:
				var dataItem Technology
				err := SelectRes.Scan(&dataItem.TechId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.techdata = append(data.techdata, dataItem)
			case 4:
				var dataItem PortDesc
				err := SelectRes.Scan(&dataItem.SpecificPortId, &dataItem.Title, &dataItem.Value)
				if err != nil { log.Fatal(err) }
				data.portdata = append(data.portdata, dataItem)
			default: break;
			}
		}
	} 
}
func getIPAddressInfo(data IpInfoLinkdataHolder) string {
	listGenInfo := func(listgen []GeneralInfo) []string {
		var ret = []string{}
		for _, val := range listgen {
			ret = append(ret, fmt.Sprintf("{'title': %s, 'value': %s}", val.Title, val.Value))
		}
		return ret
	}(data.geninfo)
	listPortInfo := func(listport []PortDesc) []string {
		var ret = []string{}
		for _, val := range listport {
			ret = append(ret, fmt.Sprintf("{'title': %s, 'value': %s}", val.Title, val.Value))
		}
		return ret
	}(data.portdata)
	listVulnInfo := func(listvuln []VulnDesc) []string {
		var ret = []string{}
		for _, val := range listvuln {
			ret = append(ret, fmt.Sprintf("{'title': %s, 'value': %s}", val.Title, val.Value))
		}
		return ret
	}(data.vulndata)
	listTagInfo := func(listtag []TagDesc) []string {
		var ret = []string{}
		for _, val := range listtag {
			ret = append(ret, val.Title)
		}
		return ret
	}(data.tagdata)
	listTechInfo := func(listTech []Technology) []string {
		var ret = []string{}
		for _, val := range listTech {
			ret = append(ret, fmt.Sprintf("{'title': '%s', 'value': '%s'}", val.Title, val.Value))
		}
		return ret
	}(data.techdata)
	return fmt.Sprintf(`{
		"ipaddress": %s,
		"geninfo": %s,
		"listport": %s,
		"listvuln": %s,
		"listtag": %s,
		"listtech": %s,
	}`, data.IPAddress, jsonArrStr(listGenInfo), jsonArrStr(listPortInfo), jsonArrStr(listVulnInfo), jsonArrStr(listTagInfo), jsonArrStr(listTechInfo))
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