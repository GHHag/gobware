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
	token, err := gobware.NewToken(expires, req.Data)

	if err != nil {
		return nil, err
	}
	
	res := &pb.CreateTokenResponse {
		EncodedToken: token,
	}

	return res, nil
}

func(s *server) CreateTokenPair(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenPairResponse, error) {
	fmt.Println("CreateTokenPair - req.Data:", req.Data)

	expires := time.Now().Add(gobware.TokenDuration)
	token, refreshToken, err := gobware.NewTokenPair(expires, req.Data)

	if err != nil {
		return nil, err
	}

	res := &pb.CreateTokenPairResponse {
		EncodedAccessToken: token,
		EncodedRefreshToken: refreshToken,
	}

	return res, nil
}

func(s *server) CheckAccessToken(ctx context.Context, req *pb.CheckAccessTokenRequest) (*pb.CheckAccessTokenResponse, error) {
	fmt.Println("CheckToken - req.EncodedToken:", req.EncodedToken)
	fmt.Println("CheckToken - req.Data:", req.Data)

	var res *pb.CheckAccessTokenResponse
	validated, _, err := gobware.VerifyToken(req.EncodedToken)
	if err != nil {
		res = &pb.CheckAccessTokenResponse {
			Access: false,
		}
	} else {
		res = &pb.CheckAccessTokenResponse {
			Access: validated,
		}
	}

	return res, nil
}

func(s *server) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessTokenResponse, error) {
	fmt.Println("CheckAccess - req.EncodedToken:", req.EncodedToken)
	fmt.Println("CheckAccess - req.Url:", req.Url)
	fmt.Println("CheckAccess - req.HttpMethod:", req.HttpMethod)
	fmt.Println("CheckAccess - req.Data:", req.Data)

	var res *pb.CheckAccessTokenResponse
	validated, accessToken, err := gobware.VerifyToken(req.EncodedToken)
	if !validated || err != nil {
		res.Access = false
	} else {
		res.Access = gobware.Config.AccessControlList.CheckAccess(accessToken.Data, req.Url, req.HttpMethod)
	}

	return res, nil
}

func(s *server) CheckRefreshToken(ctx context.Context, req *pb.CheckRefreshTokenRequest) (*pb.CheckRefreshTokenResponse, error) {
	fmt.Println("CheckToken - req.EncodedAccessToken:", req.EncodedAccessToken)
	fmt.Println("CheckToken - req.EncodedRefreshToken:", req.EncodedRefreshToken)
	// fmt.Println("CheckToken - req.Data:", req.Data)

	accessToken := req.EncodedAccessToken
	refreshToken := req.EncodedRefreshToken

	var res *pb.CheckRefreshTokenResponse
	validated, _, err := gobware.VerifyToken(accessToken)
	if !validated || err != nil {
		expires := time.Now().Add(gobware.TokenDuration)
		accessToken, refreshToken, err := gobware.AttemptTokenExchange(accessToken, refreshToken, expires)
		if err == nil {
			res.EncodedAccessToken = accessToken
			res.EncodedRefreshToken = refreshToken
		}
	} else {
		res.EncodedAccessToken = ""
		res.EncodedRefreshToken = ""
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

