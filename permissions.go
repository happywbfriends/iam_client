package iam_client

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

// NewPermissionsChecker возвращает объект типа Permissions, который
// используется для проверки прав доступа к конкретным ручкам.
// permissionsMatrix - это матрица доступа map[string][]string вида
// METHOD/URL => []string{ALLOWED_PERMISSION1[:SCOPE], ALLOWED_PERMISSION2[:SCOPE], ...}
// Например:
// POST/api/v2/admin/grant => []string{"admin:activate", "admin:promote"}
// GET/api/v1/admin/actionLog => []string{"admin", "view:log"}
//
// Если тип доступа указан без скоупа, пускаем с любым скоупом
func NewPermissionsChecker(permissionsMatrix map[string][]string, log Logger) *PermissionsChecker {
	p := PermissionsChecker{
		permissionsMatrix: permissionsMatrix,
		log:               log,
	}

	return &p
}

// PermissionsChecker используется для проверки прав доступа к конкретным ручкам
type PermissionsChecker struct {
	permissionsMatrix map[string][]string
	log               Logger
	gorillaMuxRouter  *mux.Router
	chiMuxRouter      *chi.Mux
}

// WithGorillaMuxRouter принимает на вход объект *mux.Router и применяет его при поиске
// путей в матрице доступа. Т.о. становится возможным указывать в матрице пути с макросами типа
// "POST/api/v1/admin/auth-services/{id}/activate": []string{"admin:activate"}
func (p *PermissionsChecker) WithGorillaMuxRouter(r *mux.Router) {
	p.gorillaMuxRouter = r
}

// WithChiMuxRouter принимает на вход объект *chi.Mux и применяет его при поиске
// путей в матрице доступа. Т.о. становится возможным указывать в матрице пути с макросами типа
// "POST/api/v1/admin/auth-services/{id}/activate": []string{"admin:activate"}
func (p *PermissionsChecker) WithChiMuxRouter(r *chi.Mux) {
	p.chiMuxRouter = r
}

// AuthMiddlewareHandler должен использоваться после аутентификации в IAM-клиенте.
// С правом доступа "admin:*" пускает ко всем ручкам.
// С правом доступа "view:*" пускает ко всем GET-ручкам.
// Для всех остальных прав применяется матрица доступа.
func (p *PermissionsChecker) AuthMiddlewareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userPermissions := GetPermissions(ctx)
		if len(userPermissions) == 0 {
			// Такого быть не должно, но на всякий случай обработаем в явном виде
			p.log.Errorf("Empty permissions from IAM client")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Доступ к сервису в принципе есть, добавляем id юзера в контекст
		r = r.WithContext(context.WithValue(ctx, CtxIamUserId{}, GetUserId(ctx)))

		// С админскими правами пропускаем ко всем ручкам
		if InArray(userPermissions, "admin:*") {
			next.ServeHTTP(w, r)
			return
		}

		// С полными правами на просмотр пропускаем ко всем GET-ручкам
		if r.Method == http.MethodGet && InArray(userPermissions, "view:*") {
			next.ServeHTTP(w, r)
			return
		}

		// Ищем в матрице особые разрешения для данной ручки
		allowedPermissions := p.getAllowedPermissions(r)
		if allowedPermissions == nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// У ручки нашлись особые разрешения, проверяем
		if p.checkUserPermission(allowedPermissions, userPermissions) {
			next.ServeHTTP(w, r)
			return
		}

		w.WriteHeader(http.StatusForbidden)
	})
}

func (p *PermissionsChecker) getAllowedPermissions(r *http.Request) (allowedPermissions []string) {
	var found bool
	allowedPermissions, found = p.permissionsMatrix[r.Method+r.URL.Path]
	if found {
		return
	}

	if p.gorillaMuxRouter != nil {
		match := mux.RouteMatch{}
		routeExists := p.gorillaMuxRouter.Match(r, &match)
		if routeExists {
			path, err := match.Route.GetPathTemplate()
			if err != nil {
				p.log.Errorf(err.Error())
				return nil
			}

			allowedPermissions, found = p.permissionsMatrix[r.Method+path]
			if found {
				return
			}
		}
	}

	if p.chiMuxRouter != nil {
		rctx := chi.NewRouteContext()
		if p.chiMuxRouter.Match(rctx, r.Method, r.URL.Path) {
			path := rctx.RoutePattern()
			allowedPermissions, found = p.permissionsMatrix[r.Method+path]
			if found {
				return
			}
		}
	}

	return
}

// checkUserPermission проверяет, есть ли у юзера доступ, сравнивая список прав юзера со списком разрешенных доступов.
// В списке разрешенных доступов могут быть:
// * право со скоупом, например, "view:log". Для доступа обязательно иметь в разрешениях точное совпадение "view:log".
// * право на все скоупы, например, "edit:*". Для доступа обязательно иметь в разрешениях точное совпадение "edit:*".
// * право без скоупа, например, "admin". Для доступа достаточно иметь доступ "admin" с любым скоупом.
func (p *PermissionsChecker) checkUserPermission(allowedPermissions []string, userPermissions []string) bool {
	for _, fullPermission := range userPermissions {
		basePermission := strings.SplitN(fullPermission, ":", 2)[0]
		if InArray(allowedPermissions, fullPermission) || InArray(allowedPermissions, basePermission) {
			return true
		}
	}

	return false
}

func (p *PermissionsChecker) EchoAuthMiddlewareHandler() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			ctx := r.Context()
			userPermissions := GetPermissions(ctx)
			if len(userPermissions) == 0 {
				// Такого быть не должно, но на всякий случай обработаем в явном виде
				p.log.Errorf("Empty permissions from IAM client")
				c.String(http.StatusForbidden, "Forbidden")
				return nil
			}

			// Доступ к сервису в принципе есть, добавляем id юзера в контекст
			r = r.WithContext(context.WithValue(ctx, CtxIamUserId{}, GetUserId(ctx)))
			c.SetRequest(r)

			// С админскими правами пропускаем ко всем ручкам
			if InArray(userPermissions, "admin:*") {
				return next(c)
			}

			// С полными правами на просмотр пропускаем ко всем GET-ручкам
			if r.Method == http.MethodGet && InArray(userPermissions, "view:*") {
				return next(c)
			}

			// Ищем в матрице особые разрешения для данной ручки
			allowedPermissions := p.getAllowedPermissions(r)
			if allowedPermissions == nil {
				c.String(http.StatusForbidden, "Forbidden")
				return nil
			}

			// У ручки нашлись особые разрешения, проверяем
			if p.checkUserPermission(allowedPermissions, userPermissions) {
				return next(c)
			}

			c.String(http.StatusForbidden, "Forbidden")
			return nil
		}
	}
}
