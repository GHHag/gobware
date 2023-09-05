package main

import (
	"fmt"
	"context"
	// "log"
	"net"
	"net/http"
	"time"
	"google.golang.org/grpc"
	pb "gobwarerpc/gobwarerpc"
	"github.com/GHHag/gobware"
)

// Change signature of gobware.CreateToken, make it accept a map[string]string instead of a *http.Request param, and change this function accordingly
func createToken(r *http.Request, expires time.Time, createToken gobware.CreateToken) (string, error) {
	id := "abc123"
	data := map[string]string {
		"userId": id,
		"user-role": "user",
	}

	token, err := createToken(expires, data)

	return token, err
}

// Change signature of gobware.CreateToken, make it accept a map[string]string instead of a *http.Request param, and change this function accordingly
func createTokenPair(r *http.Request, expires time.Time, createTokenPair gobware.CreateTokenPair) (string, string, error) {
	id := "abc123"
	data := map[string]string {
		"userId": id,
		"user-role": "user",
	}

	token, refreshToken, err := createTokenPair(expires, data)

	return token, refreshToken, err
}

type server struct {
	pb.UnimplementedGobwareServiceServer
	ACL gobware.ACL
}

// func(s *server) CreateACL(ctx context.Context, req *pb.CreateACLRequest) (*pb.CreateACLResponse, error) {
// 	ACL := gobware.NewACL("user-role")
//
// 	return nil, nil
// }

func(s *server) AddACLRule(ctx context.Context, req *pb.AddACLRuleRequest) (*pb.AddACLRuleResponse, error) {
	fmt.Println(req.Role)
	fmt.Println(req.Route)
	fmt.Println(req.HttpMethods)

	s.ACL.AddACLRule(req.Role, req.Route, req.HttpMethods)

	res := &pb.AddACLRuleResponse {
		successful: true,
	}

	return res, nil
}

// func(s *server) SetACL(ctx context.Context, req *pb.SetACLRequest) (*pb.SetACLResponse, error) {
// 	return nil, nil
// }

func(s *server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	expires := time.Unix(req.expires, 0)
	token, err := createToken(expires, req.data)

	if err != nil {
		return nil, err
	}
	
	res := &pb.CreateTokenResponse {
		EncodedToken: token,
	}

	return res, nil
}

func(s *server) CreateTokenPair(ctx context.Context, req *pb.CreateTokenPairRequest) (*pb.CreateTokenPairResponse, error) {
	expires := time.Unix(req.expires, 0)
	token, refreshToken, err := createTokenPair(expires, req.data)

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
	res := &pb.CheckAccessResponse {
		Access: true,
	}

	return res, nil
}

func(s *server) CheckToken(ctx context.Context, req *pb.CheckTokenRequest) (*pb.CheckTokenResponse, error) {
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
