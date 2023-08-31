package main

import (
	"context"
	// "log"
	"net"
	"google.golang.org/grpc"
	pb "gobwarerpc/gobwarerpc"
)

type server struct {
	pb.UnimplementedGobwareServiceServer
}

func(s *server) AddACLRule(ctx context.Context, req *pb.AddACLRuleRequest) (*AddACLRuleResponse, error) {

}

func(s *server) SetACL(ctx context.Context, ) (, error) {

}

func(s *server) CreateToken(ctx context.Context, ) (*CreateTokenResponse, error) {

}

func(s *server) CreateTokenPair(ctx context.Context, ) (*CreateTokenPairResponse, error) {

}

func(s *server) CheckAccess(ctx context.Context, ) (, error) {

}

func(s *server) CheckToken(ctx context.Context, ) (, error) {

}

func(s *server) Adapt(ctx context.Context, ) (, error) {

}

func main() {
	listener, err := net.Listen("tcp", ":5000")
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	pb.RegisterGobwareServiceServer(s, &server{})

	if err := s.Serve(listener); err != nil {
		panic(err)
	}
}
