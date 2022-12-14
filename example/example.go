package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/golang-jwt/jwt/v4"

	"github.com/02strich/jwt-go-aws-kms/v2/jwtkms"
)

const keyID = "aa2f90bf-f09f-42b7-b4f3-2083bd00f9ad"

func main() {
	awsCfg := aws.NewConfig().WithRegion("eu-central-1")
	sess := session.Must(session.NewSession(awsCfg))

	now := time.Now()
	jwtToken := jwt.NewWithClaims(jwtkms.SigningMethodECDSA256, &jwt.StandardClaims{
		Audience:  "api.example.com",
		ExpiresAt: now.Add(1 * time.Hour * 24).Unix(),
		Id:        "1234-5678",
		IssuedAt:  now.Unix(),
		Issuer:    "sso.example.com",
		NotBefore: now.Unix(),
		Subject:   "john.doe@example.com",
	})

	kmsConfig := jwtkms.NewKMSConfig(kms.New(sess), keyID, false)

	str, err := jwtToken.SignedString(kmsConfig.WithContext(context.Background()))
	if err != nil {
		log.Fatalf("can not sign JWT %s", err)
	}

	log.Printf("Signed JWT %s\n", str)

	claims := jwt.RegisteredClaims{}

	_, err = jwt.ParseWithClaims(str, &claims, func(token *jwt.Token) (interface{}, error) {
		return kmsConfig, nil
	})
	if err != nil {
		log.Fatalf("can not parse/verify token %s", err)
	}

	log.Printf("Parsed and validated token with claims %v", claims)
}
