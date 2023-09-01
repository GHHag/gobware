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

func(s *server) AddACLRule(ctx context.Context, req *pb.AddACLRuleRequest) (*pb.AddACLRuleResponse, error) {
	ACLRule := make(map[string]map[string]bool)

	res := &pb.AddACLRuleResponse {
		ACLRule: ACLRule,
	}

	return res, nil
}

func(s *server) SetACL(ctx context.Context, req *pb.SetACLRequest) (error) {
	return nil
}

func(s *server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	res := &pb.CreateTokenResponse {
		encodedToken: "test",
	}

	return res, nil
}

func(s *server) CreateTokenPair(ctx context.Context, req *pb.CreateTokenPairRequest) (*pb.CreateTokenPairResponse, error) {
	res := &pb.CreateTokenPairResponse {
		encodedAccessToken: "test",
		encodedRefreshToken: "test",
	}

	return res, nil
}

func(s *server) CheckAccess(ctx context.Context) (error) {
	return nil
}

func(s *server) CheckToken(ctx context.Context) (error) {
	return nil
}

func(s *server) Adapt(ctx context.Context) (error) {
	return nil
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
