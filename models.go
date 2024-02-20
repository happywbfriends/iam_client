package iam_client

// Схемы запросов/ответов IAM
// Синхронизировать с моделями в репе IAM, см. сваггер
type IAMGetAuthLinkResponse struct {
	RedirectUrl string `json:"redirect_url"`
}

type IAMGetTokenIdResponse struct {
	// Id ID токена, соответствующего code
	Id string `json:"id"`

	// Ttl Время жизни токена в секундах
	Ttl int `json:"ttl"`

	// UserEmail Еmail пользователя
	UserEmail string `json:"user_email"`

	// UserName Имя пользователя
	UserName string `json:"user_name"`
}

type IAMGetTokenPermissionsRequest struct {
	// BackURL URL, на который IAM отправит пользователя после успешной аутентификации
	BackURL string `json:"backURL"`

	// Id ID токена
	Id string `json:"id"`

	// ServiceId ID сервиса, к которому создаем или отбираем доступ
	ServiceId string `json:"service_id"`
}

type IAMGetTokenPermissionsResponse struct {
	// HttpStatus HTTP status токена
	HttpStatus  int      `json:"http_status"`
	Permissions []string `json:"permissions"`

	// RedirectUrl Ссылка на аутентификацию в Keycloak
	RedirectUrl string `json:"redirect_url"`
}
