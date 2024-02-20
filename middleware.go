package iam_client

import (
	"context"
	"net/http"
	"net/url"
)

// AuthMiddlewareHandler
func (c *Service) AuthMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Если это запрос после аутентификации в IAM, обрабатываем его
		q := r.URL.Query()
		code := q.Get("code")
		finalBackURL := q.Get("finalBackURL")
		if code != "" && finalBackURL != "" {
			c.setTokenIdHandler().ServeHTTP(w, r)
			return
		}

		// URL, на который IAM вернет пользователя после успешной аутентифицикации
		backURL, err := c.getBackURL(r)
		if err != nil {
			c.log.Errorf("s4F9pAY2DugXZd0 %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Проверяем id токена в куках
		tokenIdCk, err := r.Cookie(CookieName_TokenId)
		if err != nil {
			// Куки нет, дергаем ручку IAM getAuthLink и отдаем 401 со ссылкой в ответе
			authLinkResponse, err := c.iamClient.GetAuthLink(backURL)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			c.returnRedirectJSON(w, authLinkResponse.RedirectUrl)
			return
		}

		// Кука есть - запрашиваем у IAM пермишены по ручке getTokenPermissions
		tokenId, err := url.QueryUnescape(tokenIdCk.Value)
		if err != nil {
			c.log.Errorf("91sfK8v3s0QB5k9 %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp, err := c.iamClient.GetTokenPermissions(tokenId, c.serviceId, backURL)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Отправляем юзера на аутентификацию
		if resp.HttpStatus == http.StatusUnauthorized {
			c.returnRedirectJSON(w, resp.RedirectUrl)
			return
		}

		// Все хорошо, кладем права в контекст и идем дальше
		if resp.HttpStatus == http.StatusOK {
			r = r.WithContext(context.WithValue(r.Context(), ctxIamPermissions{}, resp.Permissions))

			next.ServeHTTP(w, r)
			return
		}

		// Получен не 200 и не 401, отдаем статус как есть
		if resp.HttpStatus != 0 {
			w.WriteHeader(resp.HttpStatus)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}
