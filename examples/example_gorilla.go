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
	r.HandleFunc("/api/v1/admin/categories/{id}", someHandler).Methods("POST")

	// Клиент IAM
	// serviceId - id нашего сервиса
	serviceId := "some_service.some_namespace"
	cfg := iam_client.Config{IamUrl: "https://foo"}
	logger := IamLogger{logger: zerolog.Logger{}}
	iamClient := iam_client.New(serviceId, cfg, logger)

	// Создаем матрицу прав. Подробности см. в описании функций iam_client.NewPermissionsChecker() и
	// PermissionChecker.AuthMiddlewareHandler().
	permissionsMatrix := make(map[string][]string)
	permissionsMatrix["GET/api/v1/admin/actionLog"] = []string{"view:log", "admin"}
	permissionsMatrix["GET/api/v1/admin/auth-services"] = []string{"admin"}
	permissionsMatrix["POST/api/v1/admin/categories/{id}"] = []string{"admin"}
	iamPermissionsChecker := iam_client.NewPermissionsChecker(permissionsMatrix, logger)
	// Без вызова этой функции не будут работать пути роутера с макросами
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
