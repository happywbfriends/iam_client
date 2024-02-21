package iam_client

import (
	"context"
	"net/http"
	"net/url"
)

const (
	HeaderAccessKey = "X-Access-Key"
)

// AuthAccessKey авторизовывает приложение по хедеру X-Access-Key
// Если хедер присутствуют, полностью берет обработку на себя, в этом случае возвращает true
func (s *Service) AuthAccessKey(w http.ResponseWriter, r *http.Request, next http.Handler) (processed bool) {
	// Проверяем наличие хедеров X-Access-Key
	accessKey := r.Header.Get(HeaderAccessKey)
	if accessKey == "" {
		return
	}

	// Ключ в хедере есть, полностью берем обработку запроса на себя
	processed = true

	// Запрашиваем у IAM пермишены
	resp, err := s.iamClient.GetAccessKeyPermissions(accessKey, s.serviceId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Все хорошо, кладем права в контекст и идем дальше
	if resp.HttpStatus == http.StatusOK {
		r = r.WithContext(context.WithValue(r.Context(), ctxIamPermissions{}, resp.Permissions))

		next.ServeHTTP(w, r)
		return
	}

	// Получен не 200, отдаем статус как есть
	w.WriteHeader(resp.HttpStatus)

	return
}

// AuthMiddlewareHandler
func (s *Service) AuthMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Шаг 1. Авторизация приложения по ключу доступа (app2app)
		// Схема авторизации app2app отличается от user2app в основном тем,
		// что в ней нет редиректа в IAM за аутентификацией
		if s.AuthAccessKey(w, r, next) {
			return
		}

		// Шаг 2. Авторизация пользователя (user2app)
		// Если это запрос после аутентификации в IAM, обрабатываем его
		q := r.URL.Query()
		code := q.Get("code")
		finalBackURL := q.Get("finalBackURL")
		if code != "" && finalBackURL != "" {
			s.setTokenIdHandler().ServeHTTP(w, r)
			return
		}

		// URL, на который IAM вернет пользователя после успешной аутентифицикации
		backURL, err := s.getBackURL(r)
		if err != nil {
			s.log.Errorf("s4F9pAY2DugXZd0 %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Проверяем id токена в куках
		tokenIdCk, err := r.Cookie(CookieName_TokenId)
		if err != nil {
			// Куки нет, дергаем ручку IAM getAuthLink и отдаем 401 со ссылкой в ответе
			authLinkResponse, err := s.iamClient.GetAuthLink(backURL)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			s.returnRedirectJSON(w, authLinkResponse.RedirectUrl)
			return
		}

		// Кука есть - запрашиваем у IAM пермишены по ручке getTokenPermissions
		tokenId, err := url.QueryUnescape(tokenIdCk.Value)
		if err != nil {
			s.log.Errorf("91sfK8v3s0QB5k9 %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp, err := s.iamClient.GetTokenPermissions(tokenId, s.serviceId, backURL)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Отправляем юзера на аутентификацию
		if resp.HttpStatus == http.StatusUnauthorized {
			s.returnRedirectJSON(w, resp.RedirectUrl)
			return
		}

		// Все хорошо, кладем права в контекст и идем дальше
		if resp.HttpStatus == http.StatusOK {
			r = r.WithContext(context.WithValue(r.Context(), ctxIamPermissions{}, resp.Permissions))

			next.ServeHTTP(w, r)
			return
		}

		// Получен не 200 и не 401, отдаем статус как есть
		w.WriteHeader(resp.HttpStatus)
	})
}
