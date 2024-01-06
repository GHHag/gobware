package main

import (
	"context"
	pb "gobwarerpc/gobwarerpc"
	"net"
	"time"

	"github.com/GHHag/gobware"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedGobwareServiceServer
	configuration gobware.Configuration
}

func (s *server) AddACLRule(ctx context.Context, req *pb.AddACLRuleRequest) (*pb.AddACLRuleResponse, error) {
	s.configuration.AddACLRule(req.Role, req.Route, req.HttpMethods)

	res := &pb.AddACLRuleResponse{
		Successful: true,
	}

	return res, nil
}

func (s *server) CreateToken(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenResponse, error) {
	expires := time.Now().Add(gobware.TokenDuration)
	token, err := gobware.NewToken(expires, req.Data)

	if err != nil {
		return nil, err
	}

	res := &pb.CreateTokenResponse{
		EncodedToken: token,
	}

	return res, nil
}

func (s *server) CreateTokenPair(ctx context.Context, req *pb.CreateTokenRequest) (*pb.CreateTokenPairResponse, error) {
	expires := time.Now().Add(gobware.TokenDuration)
	token, refreshToken, err := gobware.NewTokenPair(expires, req.Data)

	if err != nil {
		return nil, err
	}

	res := &pb.CreateTokenPairResponse{
		EncodedAccessToken:  token,
		EncodedRefreshToken: refreshToken,
	}

	return res, nil
}

func (s *server) CheckAccessToken(ctx context.Context, req *pb.CheckAccessTokenRequest) (*pb.CheckAccessTokenResponse, error) {
	var res *pb.CheckAccessTokenResponse
	validated, _, err := gobware.VerifyToken(req.EncodedToken)
	if err != nil {
		res = &pb.CheckAccessTokenResponse{
			Access: false,
		}
	} else {
		res = &pb.CheckAccessTokenResponse{
			Access: validated,
		}
	}

	return res, nil
}

func (s *server) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessTokenResponse, error) {
	var res *pb.CheckAccessTokenResponse
	validated, accessToken, err := gobware.VerifyToken(req.EncodedToken)
	if err != nil {
		res = &pb.CheckAccessTokenResponse{
			Validated: false,
			Access:    false,
		}
	} else {
		res = &pb.CheckAccessTokenResponse{
			Validated: validated,
			Access:    s.configuration.CheckAccess(accessToken.Data, req.Url, req.HttpMethod),
		}
	}

	return res, nil
}

func (s *server) CheckRefreshToken(ctx context.Context, req *pb.CheckRefreshTokenRequest) (*pb.CheckRefreshTokenResponse, error) {
	accessToken := req.EncodedAccessToken
	refreshToken := req.EncodedRefreshToken

	var res *pb.CheckRefreshTokenResponse
	validated, _, err := gobware.VerifyToken(accessToken)
	if !validated || err != nil {
		expires := time.Now().Add(gobware.TokenDuration)
		accessToken, refreshToken, err := gobware.AttemptTokenExchange(accessToken, refreshToken, expires)
		res = &pb.CheckRefreshTokenResponse{
			EncodedAccessToken:  accessToken,
			EncodedRefreshToken: refreshToken,
		}
		if err == nil {
			res.Successful = true
		} else {
			res.Successful = false
		}
	} else {
		res = &pb.CheckRefreshTokenResponse{
			EncodedAccessToken:  accessToken,
			EncodedRefreshToken: refreshToken,
			Successful:          true,
		}
	}

	return res, nil
}

func (s *server) ParseTokenData(ctx context.Context, req *pb.CheckAccessTokenRequest) (*pb.ParseTokenDataResponse, error) {
	accessToken := req.EncodedToken
	var res *pb.ParseTokenDataResponse
	validated, token, err := gobware.VerifyToken(accessToken)
	if validated && err == nil {
		res = &pb.ParseTokenDataResponse{
			Data:       token.Data,
			Successful: true,
		}
	} else {
		res = &pb.ParseTokenDataResponse{
			Data:       make(map[string]string),
			Successful: false,
		}
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

	config := gobware.Configuration{}
	ACL := gobware.NewACL("user-role")
	config.SetACL(ACL)

	app := &server{
		configuration: config,
	}

	pb.RegisterGobwareServiceServer(s, app)

	if err := s.Serve(listener); err != nil {
		panic(err)
	}
}
