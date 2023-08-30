package main

import(
	"fmt"
	// "context"
	// "log"
	// "google.golang.org/grpc"
	// pb "gobwarerpc"
)

type server struct {
	pb.UnimplementedGobwareServiceServer
}

func main(){
	fmt.Println("Hello gobware")
}
