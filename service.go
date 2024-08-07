package iam_client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

const (
	CookieName_TokenId   = "iam_token_id"
	CookieName_UserEmail = "UserEmail"
	CookieName_UserName  = "UserName"
)

var ErrEmptyReferer = errors.New("Empty referer")

type CtxIamPermissions struct{}
type CtxIamUserId struct{}

// New создает объект сервиса со стандартным HTTP клиентом
func New(serviceId string, cfg Config, logger Logger) *Service {
	return NewWithHTTPClient(serviceId, cfg, logger, http.DefaultClient)
}

// NewWithHTTPClient создает объект сервиса с заранее созданным HTTP клиентом
func NewWithHTTPClient(serviceId string, cfg Config, logger Logger, httpClient *http.Client) *Service {
	return &Service{
		log:       logger,
		iamClient: NewIamClient(serviceId, cfg.IamUrl, logger, httpClient),
		serviceId: serviceId,
	}
}

type Service struct {
	log       Logger
	iamClient *IamClient
	serviceId string
}

type link401 struct {
	RedirectURL string `json:"redirect_url"`
}

// SetHTTPClient позволяет установить HTTP клиента уже после создания объекта сервиса
func (s *Service) SetHTTPClient(httpClient *http.Client) {
	s.iamClient.SetHTTPClient(httpClient)
}

// setTokenIdHandler Специальный хэндлер, использующийся для установки куки с token_id.
// Код ручки берет параметр "code" и в фоновом режиме обращается с ним к IAM на ручку /api/v2/getTokenId,
// получает в ответ "token_id" и прописывает его в куку "token_id".
func (s *Service) setTokenIdHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("code")
		if code == "" {
			s.log.Errorf("empty code param")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("empty code param"))
			return
		}
		finalBackURL := q.Get("finalBackURL")
		_, err := url.ParseRequestURI(finalBackURL)
		if err != nil {
			s.log.Errorf("Wd8015Wu3iPlzZA %s", err)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("incorrect finalBackURL"))
			return
		}

		tokenIdResponse, err := s.iamClient.GetTokenId(code)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Выставляем данные в куки
		s.setCookie(w, r, CookieName_UserEmail, url.QueryEscape(tokenIdResponse.UserEmail), tokenIdResponse.Ttl, false)
		s.setCookie(w, r, CookieName_UserName, url.QueryEscape(tokenIdResponse.UserName), tokenIdResponse.Ttl, false)
		s.setCookie(w, r, CookieName_TokenId, url.QueryEscape(tokenIdResponse.Id), tokenIdResponse.Ttl, true)

		http.Redirect(w, r, finalBackURL, http.StatusTemporaryRedirect)
	})
}

// getBackURL формирует backURL, на который IAM вернет пользователя после успешной аутентифицикации
// Это ссылка на ручку вида /api/v1/REQUEST?finalBackURL=<finalBackURL>
// Где finalBackURL - это URL, на который надо будет вернуть пользователя в самом конце цепочки.
// Т.е. это URL, на котором сейчас находится пользователь, а, точнее, реферер.
func (s *Service) getBackURL(r *http.Request) (string, error) {
	// URL, на который надо будет финально вернуть пользователя в самом конце цепочки
	finalBackURL := r.Referer()
	if finalBackURL == "" {
		return "", ErrEmptyReferer
	}

	// URL текущего запроса к АПИ, на него надо будет вернуть пользователя после успешной аутентифицикации в IAM
	requestURL := s.getRequestURL(r)
	if strings.Contains(requestURL, "?") {
		requestURL += "&finalBackURL=" + url.QueryEscape(finalBackURL)
	} else {
		requestURL += "?finalBackURL=" + url.QueryEscape(finalBackURL)
	}

	return requestURL, nil
}

func (s *Service) returnRedirectJSON(w http.ResponseWriter, redirectURL string) {
	data, _ := json.Marshal(link401{RedirectURL: redirectURL})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(data)
}

// getRequestURL возвращает URL текущего запроса АПИ. На него надо будет вернуть
// пользователя после успешной аутентификации в IAM
func (s *Service) getRequestURL(r *http.Request) string {
	// Если передан заголовок X-Original-Request-Uri, то берем его.
	// Он м.б. установлен даунстримом, если сервис подключен с помощью proxy_pass в nginx,
	// в этом случае нам важно вернуть пользователя именно по этому URI.
	uri := r.Header.Get("X-Original-Request-Uri")
	if uri == "" {
		uri = r.URL.RequestURI()
	}

	return "https://" + strings.Trim(r.Host, "/") + uri
}

func (s *Service) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxage int, isHttpOnly bool) {
	ck := &http.Cookie{
		Name:     name,
		Domain:   r.Host,
		Path:     "/",
		HttpOnly: isHttpOnly,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Value:    value,
		MaxAge:   maxage,
	}

	http.SetCookie(w, ck)
}

func GetPermissions(ctx context.Context) []string {
	permissions := ctx.Value(CtxIamPermissions{})
	if result, ok := permissions.([]string); ok {
		return result
	}

	return nil
}

func GetUserId(ctx context.Context) string {
	userId := ctx.Value(CtxIamUserId{})
	if userId == nil {
		return ""
	}

	return fmt.Sprintf("%s", userId)
}
