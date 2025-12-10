package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Replace with your credentials and database name
	dsn := "root:@tcp(127.0.0.1:3306)/passagem_passagemain?multiStatements=true"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Increase max_allowed_packet (if needed)
	_, err = db.Exec("SET GLOBAL max_allowed_packet=268435456") // 256 MB
	if err != nil {
		fmt.Println("Warning: couldn't set max_allowed_packet:", err)
	}

	// Open the large SQL file
	file, err := os.Open("shotan.sql")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	var statement strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}

		// Accumulate SQL statements
		statement.WriteString(line)

		// Check for end of SQL command
		if strings.HasSuffix(strings.TrimSpace(line), ";") {
			sqlCmd := statement.String()
			_, execErr := db.Exec(sqlCmd)
			if execErr != nil {
				fmt.Println("error execute command")
				// fmt.Println("Error executing:", sqlCmd)
				// fmt.Println("→", execErr)
			}
			statement.Reset()
		}

		if err == io.EOF {
			break
		}
	}

	fmt.Println("SQL import complete.")
}
