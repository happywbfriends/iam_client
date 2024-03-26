package iam_client

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

func TestPermissionsChecker_checkUserPermission(t *testing.T) {
	type args struct {
		allowedPermissions []string
		userPermissions    []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Empty lists",
			args: args{
				allowedPermissions: nil,
				userPermissions:    nil,
			},
			want: false,
		},

		{
			name: "Empty user permissions",
			args: args{
				allowedPermissions: []string{"admin:promote", "view"},
				userPermissions:    nil,
			},
			want: false,
		},

		{
			name: "Empty allowed permissions",
			args: args{
				allowedPermissions: nil,
				userPermissions:    []string{"admin:dismiss", "view"},
			},
			want: false,
		},

		{
			name: "No access",
			args: args{
				allowedPermissions: []string{"admin:promote"},
				userPermissions:    []string{"admin:dismiss", "view"},
			},
			want: false,
		},

		{
			name: "Requires a full permission with a scope, has an access",
			args: args{
				allowedPermissions: []string{"view:log"},
				userPermissions:    []string{"edit:*", "view:log"},
			},
			want: true,
		},

		{
			name: "Requires the permission with any scope, has an access",
			args: args{
				allowedPermissions: []string{"view"},
				userPermissions:    []string{"edit:*", "view:log"},
			},
			want: true,
		},

		{
			name: "Requires the permission with any scope, no access",
			args: args{
				allowedPermissions: []string{"admin"},
				userPermissions:    []string{"edit:*", "view:log"},
			},
			want: false,
		},

		{
			name: "Requires the permission for all scopes, has an access",
			args: args{
				allowedPermissions: []string{"edit:*"},
				userPermissions:    []string{"edit:*", "view:log"},
			},
			want: true,
		},

		{
			name: "Requires the permission for all scopes, no access",
			args: args{
				allowedPermissions: []string{"edit:*"},
				userPermissions:    []string{"edit:promote", "view:log"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PermissionsChecker{}
			if got := p.checkUserPermission(tt.args.allowedPermissions, tt.args.userPermissions); got != tt.want {
				t.Errorf("checkUserPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermissionsChecker_getAllowedPermissionsWithGorillaMuxRouter(t *testing.T) {
	// Общий router
	router := mux.NewRouter().StrictSlash(true).PathPrefix("/").Subrouter()
	router.HandleFunc("/api/v1/admin/auth-services/{id}/activate", nil).Methods("POST")

	type args struct {
		method string
		path   string
	}
	tests := []struct {
		name              string
		permissionsMatrix map[string][]string
		args              args
		gorillaMuxRouter  *mux.Router
		want              []string
	}{
		{
			name: "Simple path with some permissions",
			permissionsMatrix: map[string][]string{
				"GET/api/v1/admin/actionLog":     []string{"view:log", "admin"},
				"GET/api/v1/admin/auth-services": []string{"admin"},
			},
			gorillaMuxRouter: router,
			args: args{
				method: "GET",
				path:   "/api/v1/admin/actionLog",
			},
			want: []string{"view:log", "admin"},
		},

		{
			name: "Simple path without particular permissions",
			permissionsMatrix: map[string][]string{
				"GET/api/v1/admin/actionLog":     []string{"view:log", "admin"},
				"GET/api/v1/admin/auth-services": []string{"admin"},
			},
			gorillaMuxRouter: router,
			args: args{
				method: "GET",
				path:   "/api/v1/admin/categories",
			},
			want: nil,
		},

		{
			name: "Complex path with some permissions",
			permissionsMatrix: map[string][]string{
				"POST/api/v1/admin/auth-services/{id}/activate": []string{"admin:activate"},
				"GET/api/v1/admin/auth-services":                []string{"admin"},
			},
			gorillaMuxRouter: router,
			args: args{
				method: "POST",
				path:   "/api/v1/admin/auth-services/123/activate",
			},
			want: []string{"admin:activate"},
		},

		{
			name: "Complex path with some permissions without mux router (won't detect a path with curly brackets)",
			permissionsMatrix: map[string][]string{
				"POST/api/v1/admin/auth-services/{id}/activate": []string{"admin:activate"},
				"GET/api/v1/admin/auth-services":                []string{"admin"},
			},
			gorillaMuxRouter: nil,
			args: args{
				method: "POST",
				path:   "/api/v1/admin/auth-services/123/activate",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPermissionsChecker(tt.permissionsMatrix, nil)
			r := http.Request{
				Method: tt.args.method,
				URL:    &url.URL{Path: tt.args.path},
			}
			p.WithGorillaMuxRouter(tt.gorillaMuxRouter)

			if got := p.getAllowedPermissions(&r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAllowedPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermissionsChecker_getAllowedPermissionsWithChiMuxRouter(t *testing.T) {
	// Общий router
	router := chi.NewRouter()
	router.Post("/api/v1/admin/auth-services/{id}/activate", nil)

	type args struct {
		method string
		path   string
	}
	tests := []struct {
		name              string
		permissionsMatrix map[string][]string
		args              args
		chiMuxRouter      *chi.Mux
		want              []string
	}{
		{
			name: "Simple path with some permissions",
			permissionsMatrix: map[string][]string{
				"GET/api/v1/admin/actionLog":     []string{"view:log", "admin"},
				"GET/api/v1/admin/auth-services": []string{"admin"},
			},
			chiMuxRouter: router,
			args: args{
				method: "GET",
				path:   "/api/v1/admin/actionLog",
			},
			want: []string{"view:log", "admin"},
		},

		{
			name: "Simple path without particular permissions",
			permissionsMatrix: map[string][]string{
				"GET/api/v1/admin/actionLog":     []string{"view:log", "admin"},
				"GET/api/v1/admin/auth-services": []string{"admin"},
			},
			chiMuxRouter: router,
			args: args{
				method: "GET",
				path:   "/api/v1/admin/categories",
			},
			want: nil,
		},

		{
			name: "Complex path with some permissions",
			permissionsMatrix: map[string][]string{
				"POST/api/v1/admin/auth-services/{id}/activate": []string{"admin:activate"},
				"GET/api/v1/admin/auth-services":                []string{"admin"},
			},
			chiMuxRouter: router,
			args: args{
				method: "POST",
				path:   "/api/v1/admin/auth-services/123/activate",
			},
			want: []string{"admin:activate"},
		},

		{
			name: "Complex path with some permissions without mux router (won't detect a path with curly brackets)",
			permissionsMatrix: map[string][]string{
				"POST/api/v1/admin/auth-services/{id}/activate": []string{"admin:activate"},
				"GET/api/v1/admin/auth-services":                []string{"admin"},
			},
			chiMuxRouter: nil,
			args: args{
				method: "POST",
				path:   "/api/v1/admin/auth-services/123/activate",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPermissionsChecker(tt.permissionsMatrix, nil)
			r := http.Request{
				Method: tt.args.method,
				URL:    &url.URL{Path: tt.args.path},
			}
			p.WithChiMuxRouter(tt.chiMuxRouter)

			if got := p.getAllowedPermissions(&r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAllowedPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}
