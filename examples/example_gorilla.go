package examples

import (
	"github.com/gorilla/mux"
	"github.com/happywbfriends/iam_client"
	"net/http"
)
import "github.com/rs/zerolog"

func gorillaMuxRouter(r *mux.Router) {
	// Ручки роутера
	r.HandleFunc("/api/v1/admin/actionLog", someHandler).Methods("GET")
	r.HandleFunc("/api/v1/admin/auth-services", someHandler).Methods("GET")
	r.HandleFunc("/api/v1/admin/category/{id}", someHandler).Methods("GET")
	r.HandleFunc("/api/v1/admin/category/{id}", someHandler).Methods("POST")

	// Клиент IAM
	// serviceId - id нашего сервиса
	serviceId := "some_service.some_namespace"
	cfg := iam_client.Config{IamUrl: "https://foo"}
	logger := IamLogger{logger: zerolog.Logger{}}
	iamClient := iam_client.New(serviceId, cfg, logger)

	// Матрица прав доступа. Подробности см. в описании функций iam_client.NewPermissionsChecker() и
	// PermissionChecker.AuthMiddlewareHandler().
	// Алгоритм:
	// * с правом доступа "admin:*" пускаем ко всем ручкам
	// * с правом доступа "view:*" пускаем ко всем GET-ручкам
	// * для всех остальных прав применяется матрица доступа
	permissionsMatrix := make(map[string][]string)

	// Разрешен доступ с правами:
	// "admin:*", "view:*", "view:log", "admin:log"
	permissionsMatrix["GET/api/v1/admin/actionLog"] = []string{"view:log", "admin:log"}

	// Если у разрешенного права опущен скоуп, пускаем с любым скоупом, т.е. в данном случае
	// подойдет любой вариант из: "admin:*", "admin:view" и т.п.
	// Т.о. разрешен доступ с правами:
	// "admin:*", "view:*", "admin:scope1", "admin:scope2", ...
	permissionsMatrix["GET/api/v1/admin/auth-services"] = []string{"admin"}

	// Разрешен доступ с правами:
	// "admin:*", "view:*", "view:log"
	permissionsMatrix["GET/api/v1/admin/category/{id}"] = []string{"view:log"}

	// POST-ручка, своего правила нет, так что в данном случае будет разрешен доступ только с правом "admin:*".
	// Если строку раскомментировать, будет разрешен доступ с правами:
	// "admin:*", "edit:category"
	// permissionsMatrix["POST/api/v1/admin/category/{id}"] = []string{"edit:category"}

	// Проверяльщик прав доступа
	iamPermissionsChecker := iam_client.NewPermissionsChecker(permissionsMatrix, logger)
	// Вызов WithGorillaMuxRouter нужен, чтобы заработали пути роутера с макросами
	iamPermissionsChecker.WithGorillaMuxRouter(r)

	r.Use(
		// Аутентификация пользователя (по ключу ИЛИ по кукам)
		iamClient.AuthMiddlewareHandler,

		// AuthMiddlewareHandler должен использоваться после аутентификации в IAM-клиенте.
		// С правом доступа "admin:*" пускает ко всем ручкам.
		// С правом доступа "view:*" пускает ко всем GET-ручкам.
		// Для всех остальных прав применяется матрица доступа.
		iamPermissionsChecker.AuthMiddlewareHandler,
	)
}

func someHandler(w http.ResponseWriter, r *http.Request) {
}
