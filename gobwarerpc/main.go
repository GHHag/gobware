package main

import (
	"fmt"
	"context"
	// "log"
	"net"
	"time"
	"google.golang.org/grpc"
	pb "gobwarerpc/gobwarerpc"
	"github.com/GHHag/gobware"
)

// If equal function is defined in gobware, use that instead
func createToken(expires time.Time, data map[string]string, createToken gobware.CreateToken) (string, error) {
	token, err := createToken(expires, data)

	return token, err
}

// If equal function is defined in gobware, use that instead
func createTokenPair(expires time.Time, data map[string]string, createTokenPair gobware.CreateTokenPair) (string, string, error) {
	token, refreshToken, err := createTokenPair(expires, data)

	return token, refreshToken, err
}

type server struct {
	pb.UnimplementedGobwareServiceServer
	ACL gobware.ACL
}

func(s *server) AddACLRule(ctx context.Context, req *pb.AddACLRuleRequest) (*pb.AddACLRuleResponse, error) {
	fmt.Println("AddACLRule - req.Role:", req.Role)
	fmt.Println("AddACLRule - req.Route:", req.Route)
	fmt.Println("AddACLRule - req.HttpMethods:", req.HttpMethods)

	s.ACL.AddACLRule(req.Role, req.Route, req.HttpMethods)

	res := &pb.AddACLRuleResponse {
		Successful: true,
	}

	return res, nil
}

func(s *server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	fmt.Println("CreateToken - req.Data:", req.Data)

	expires := time.Now().Add(gobware.TokenDuration)
	token, err := createToken(expires, req.Data, gobware.NewToken)

	if err != nil {
		return nil, err
	}
	
	res := &pb.CreateTokenResponse {
		EncodedToken: token,
	}

	return res, nil
}

func(s *server) CreateTokenPair(ctx context.Context, req *pb.CreateTokenPairRequest) (*pb.CreateTokenPairResponse, error) {
	fmt.Println("CreateTokenPair - req.Data:", req.Data)

	expires := time.Now().Add(gobware.TokenDuration)
	token, refreshToken, err := createTokenPair(expires, req.Data, gobware.NewTokenPair)

	if err != nil {
		return nil, err
	}

	res := &pb.CreateTokenPairResponse {
		EncodedAccessToken: token,
		EncodedRefreshToken: refreshToken,
	}

	return res, nil
}

func(s *server) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
	fmt.Println("CheckAccess - req.EncodedToken:", req.EncodedToken)
	fmt.Println("CheckAccess - req.Data:", req.Data)

	res := &pb.CheckAccessResponse {
		Access: true,
	}

	return res, nil
}

func(s *server) CheckToken(ctx context.Context, req *pb.CheckTokenRequest) (*pb.CheckTokenResponse, error) {
	fmt.Println("CheckToken - req.EncodedToken:", req.EncodedToken)
	fmt.Println("CheckToken - req.Data:", req.Data)

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

	ACL := gobware.NewACL("user-role")
	gobware.SetACL(ACL)

	app := &server{
		ACL: ACL,
	}

	pb.RegisterGobwareServiceServer(s, app)

	if err := s.Serve(listener); err != nil {
		panic(err)
	}
}
