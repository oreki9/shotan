package main
import (
	"fmt"
	cmd "github.com/oreki9/shotan/searchcli"
)

func main(){
	fmt.Println(cmd.handler("search", "49.0.252.39", "cosco", 1))
}