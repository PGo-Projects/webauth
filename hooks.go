package webauth

import "net/http"

type hook func(w http.ResponseWriter, r *http.Request) error

var (
	registerSuccessHooks = []hook{}
	loginSuccessHooks    = []hook{}
	logoutSuccessHooks   = []hook{}
)

func AddRegisterSuccessHook(h hook) {
	registerSuccessHooks = append(registerSuccessHooks, h)
}

func AddLoginSuccessHook(h hook) {
	loginSuccessHooks = append(loginSuccessHooks, h)
}

func AddLogoutSuccessHook(h hook) {
	logoutSuccessHooks = append(logoutSuccessHooks, h)
}

func runHooks(hooks []hook, w http.ResponseWriter, r *http.Request) error {
	for _, h := range hooks {
		if err := h(w, r); err != nil {
			return err
		}
	}
	return nil
}
