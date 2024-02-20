package iam_client

type Config struct {
	// URL сервиса IAM
	IamUrl string `env:"IAM_URL,required"`
}
