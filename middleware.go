package iam_client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

const (
	HeaderAccessKey = "X-Access-Key"
)

// AuthAccessKey аутентифицирует приложение по хедеру X-Access-Key
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
		r = r.WithContext(context.WithValue(r.Context(), CtxIamPermissions{}, resp.Permissions))

		r = r.WithContext(context.WithValue(r.Context(), CtxIamUserId{}, resp.UserId))

		next.ServeHTTP(w, r)
		return
	}

	// Получен не 200, отдаем статус как есть
	w.WriteHeader(resp.HttpStatus)

	return
}

// AuthAccessKeyMiddleware миддлварь для проверки доступа только по ключу
func (s *Service) AuthAccessKeyMiddleware(_ http.ResponseWriter, r *http.Request) (*http.Request, error) {
	accessKey := r.Header.Get(HeaderAccessKey)
	if accessKey == "" {
		return r, errors.New("X-Access-Key is missing")
	}

	// Запрашиваем у IAM пермишены
	resp, err := s.iamClient.GetAccessKeyPermissions(accessKey, s.serviceId)
	if err != nil {
		return r, err
	}

	// Получен не 200, отдаем статус как есть
	if resp.HttpStatus != http.StatusOK {
		return r, errors.Errorf("unauthorized: %d", resp.HttpStatus)
	}

	// Все хорошо, кладем права в контекст и идем дальше
	r = r.WithContext(context.WithValue(r.Context(), CtxIamPermissions{}, resp.Permissions))

	r = r.WithContext(context.WithValue(r.Context(), CtxIamUserId{}, resp.UserId))

	return r, nil
}

// AuthMiddlewareHandler выполняет аутентификацию пользователя (по ключу ИЛИ по кукам)
func (s *Service) AuthMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Шаг 1. Аутентификация приложения по ключу доступа (app2app)
		// Схема аутентификации app2app отличается от user2app в основном тем,
		// что в ней нет редиректа в IAM за аутентификацией
		if s.AuthAccessKey(w, r, next) {
			return
		}

		// Шаг 2. Аутентификация пользователя (user2app)
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
			if errors.Is(err, ErrEmptyReferer) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(ErrEmptyReferer.Error()))
				return
			}

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

		// Отправляем юзера на аутентификацию в IAM
		if resp.HttpStatus == http.StatusUnauthorized {
			s.returnRedirectJSON(w, resp.RedirectUrl)
			return
		}

		// Все хорошо, кладем права в контекст и идем дальше
		if resp.HttpStatus == http.StatusOK {
			r = r.WithContext(context.WithValue(r.Context(), CtxIamPermissions{}, resp.Permissions))

			// Добавляем содержимое куки CookieName_UserEmail как userId
			var userEmail string
			userEmailCk, err := r.Cookie(CookieName_UserEmail)
			if err != nil {
				// Такого быть не должно ругнемся в лог
				s.log.Errorf("No cookie %s", CookieName_UserEmail)
			} else {
				userEmail, err = url.QueryUnescape(userEmailCk.Value)
				if err != nil {
					s.log.Errorf("6k5X83JDf2cI11V %s", err)
				}
			}
			r = r.WithContext(context.WithValue(r.Context(), CtxIamUserId{}, userEmail))

			next.ServeHTTP(w, r)
			return
		}

		// Получен не 200 и не 401, отдаем статус как есть
		w.WriteHeader(resp.HttpStatus)
	})
}

// SimpleAuthMiddlewareHandler отличается от AuthMiddlewareHandler тем, что не запрашивает у IAM права доступа к конкретному сервису.
// Вместо этого у IAM проверяется лишь то, что у пользователя валидный ID токена в куках.
// Этот метод понадобился для самой админки IAM, в которой есть ручка /iam/v2/permissions - доступ к ней должен быть закрыт кейклоком,
// но при этом пользовательские запросы к ней не привязаны к конкретному сервису.
// Эта middleware работает только с куками, ключи доступа в ней не обрабатываются.
// Эта middleware не выставляет статус 403. Возможны только 200, 401 и 503.
func (s *Service) SimpleAuthMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Авторизация пользователя (user2app)
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
			if errors.Is(err, ErrEmptyReferer) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(ErrEmptyReferer.Error()))
				return
			}

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

		resp, err := s.iamClient.IsTokenValid(tokenId)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Токен невалиден, отдаем 401
		if !resp.Success {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Токен валиден, пропускаем
		next.ServeHTTP(w, r)
	})
}

func InArray[T comparable](a []T, x T) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == x {
			return true
		}
	}
	return false
}

// EchoAuthAccessKey - аналог AuthAccessKey, написанный под роутер echo
func (s *Service) EchoAuthAccessKey(c echo.Context, next echo.HandlerFunc) (processed bool, err error) {
	r := c.Request()

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
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Все хорошо, кладем права в контекст и идем дальше
	if resp.HttpStatus == http.StatusOK {
		r = r.WithContext(context.WithValue(r.Context(), CtxIamPermissions{}, resp.Permissions))

		r = r.WithContext(context.WithValue(r.Context(), CtxIamUserId{}, resp.UserId))

		c.SetRequest(r)

		err = next(c)
		return
	}

	// Получен не 200, отдаем статус как есть
	c.String(resp.HttpStatus, "")

	return
}

// EchoAuthMiddlewareHandler - аналог AuthMiddlewareHandler, написанный под роутер echo
func (s *Service) EchoAuthMiddlewareHandler() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Шаг 1. Авторизация приложения по ключу доступа (app2app)
			// Схема авторизации app2app отличается от user2app в основном тем,
			// что в ней нет редиректа в IAM за аутентификацией
			processed, err := s.EchoAuthAccessKey(c, next)
			if processed {
				return err
			}

			r := c.Request()
			w := c.Response().Writer

			// Шаг 2. Авторизация пользователя (user2app)
			// Если это запрос после аутентификации в IAM, обрабатываем его
			q := r.URL.Query()
			code := q.Get("code")
			finalBackURL := q.Get("finalBackURL")
			if code != "" && finalBackURL != "" {
				s.setTokenIdHandler().ServeHTTP(w, r)
				return nil
			}

			// URL, на который IAM вернет пользователя после успешной аутентифицикации
			backURL, err := s.getBackURL(r)
			if err != nil {
				if errors.Is(err, ErrEmptyReferer) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(ErrEmptyReferer.Error()))
					return nil
				}

				s.log.Errorf("s4F9pAY2DugXZd0 %s", err)
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			}

			// Проверяем id токена в куках
			tokenIdCk, err := r.Cookie(CookieName_TokenId)
			if err != nil {
				// Куки нет, дергаем ручку IAM getAuthLink и отдаем 401 со ссылкой в ответе
				authLinkResponse, err := s.iamClient.GetAuthLink(backURL)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return nil
				}

				s.returnRedirectJSON(w, authLinkResponse.RedirectUrl)
				return nil
			}

			// Кука есть - запрашиваем у IAM пермишены по ручке getTokenPermissions
			tokenId, err := url.QueryUnescape(tokenIdCk.Value)
			if err != nil {
				s.log.Errorf("91sfK8v3s0QB5k9 %s", err)
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			}

			resp, err := s.iamClient.GetTokenPermissions(tokenId, s.serviceId, backURL)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			}

			// Отправляем юзера на аутентификацию
			if resp.HttpStatus == http.StatusUnauthorized {
				s.returnRedirectJSON(w, resp.RedirectUrl)
				return nil
			}

			// Все хорошо, кладем права в контекст и идем дальше
			if resp.HttpStatus == http.StatusOK {
				r = r.WithContext(context.WithValue(r.Context(), CtxIamPermissions{}, resp.Permissions))

				// Добавляем содержимое куки CookieName_UserEmail как userId
				var userEmail string
				userEmailCk, err := r.Cookie(CookieName_UserEmail)
				if err != nil {
					// Такого быть не должно ругнемся в лог
					s.log.Errorf("No cookie %s", CookieName_UserEmail)
				} else {
					userEmail, err = url.QueryUnescape(userEmailCk.Value)
					if err != nil {
						s.log.Errorf("6k5X83JDf2cI11V %s", err)
					}
				}
				r = r.WithContext(context.WithValue(r.Context(), CtxIamUserId{}, userEmail))

				c.SetRequest(r)

				return next(c)
			}

			// Получен не 200 и не 401, отдаем статус как есть
			w.WriteHeader(resp.HttpStatus)

			return nil
		}
	}
}
