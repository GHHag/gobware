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
	// ACLRule := make(map[string]map[string]bool)
	ACLRule := &pb.ACLRule {
		HttpMethod: "test",
		Access: true,
	}
	ACLRules := make(map[string]*pb.ACLRule) 
	ACLRules ["test"] = ACLRule

	res := &pb.AddACLRuleResponse {
		ACLRules: ACLRules,
	}

	return res, nil
}

func(s *server) SetACL(ctx context.Context, req *pb.SetACLRequest) (*pb.SetACLResponse, error) {
	return nil, nil
}

func(s *server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	res := &pb.CreateTokenResponse {
		EncodedToken: "test",
	}

	return res, nil
}

func(s *server) CreateTokenPair(ctx context.Context, req *pb.CreateTokenPairRequest) (*pb.CreateTokenPairResponse, error) {
	res := &pb.CreateTokenPairResponse {
		EncodedAccessToken: "test",
		EncodedRefreshToken: "test",
	}

	return res, nil
}

func(s *server) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
	// return true
	res := &pb.CheckAccessResponse {
		Access: true,
	}

	return res, nil
}

func(s *server) CheckToken(ctx context.Context, req *pb.CheckTokenRequest) (*pb.CheckTokenResponse, error) {
	// return true
	res := &pb.CheckTokenResponse {
		Access: true,
	}

	return res, nil
}

// func(s *server) Adapt(ctx context.Context) (error) {
// 	return nil
// }

func main() {
	listener, err := net.Listen("tcp", ":5000")
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	// s := pb.GobwareServiceServer()
	pb.RegisterGobwareServiceServer(s, &server{})

	if err := s.Serve(listener); err != nil {
		panic(err)
	}
}
