package webauth

import "net/http"

type hook func(w http.ResponseWriter, r *http.Request, credentials Credentials) error
type simpleHook func(w http.ResponseWriter, r *http.Request) error

var (
	registerSuccessHooks = []hook{}
	loginSuccessHooks    = []hook{}
	logoutSuccessHooks   = []simpleHook{}
)

func AddRegisterSuccessHook(h hook) {
	registerSuccessHooks = append(registerSuccessHooks, h)
}

func AddLoginSuccessHook(h hook) {
	loginSuccessHooks = append(loginSuccessHooks, h)
}

func AddLogoutSuccessHook(h simpleHook) {
	logoutSuccessHooks = append(logoutSuccessHooks, h)
}

func runHooks(hooks []hook, w http.ResponseWriter, r *http.Request, c Credentials) error {
	for _, h := range hooks {
		if err := h(w, r, c); err != nil {
			return err
		}
	}
	return nil
}

func runSimpleHooks(hooks []simpleHook, w http.ResponseWriter, r *http.Request) error {
	for _, h := range hooks {
		if err := h(w, r); err != nil {
			return err
		}
	}
	return nil
}
