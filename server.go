package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    if(r.URL.Path == "detail"){
		name := r.URL.Query().Get("ip") // Extract "name" parameter from URL
		// if name == "" {
		// 	name = "Guest" // Default value if "name" is missing
		// }
		// fmt.Println(r.URL.RawQuery)
		fmt.Fprintf(w, "Hello, World!")
	}else{
		fmt.Fprintf(w, "No Response")
	}
}
func main() {
    http.HandleFunc("/", handler) // Route "/"
    
    fmt.Println("Server running on http://localhost:8080")
    http.ListenAndServe(":8080", nil) // Start server on port 8080
}
