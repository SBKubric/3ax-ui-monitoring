package probe

import (
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

func TestBudgetsFrom(t *testing.T) {
	t.Run("document values win", func(t *testing.T) {
		got := BudgetsFrom(proto.ProbeParams{BudgetMs: 15000, ConnectMs: 3000, TlsMs: 7000, HeadersMs: 8000})
		want := Budgets{
			Budget:  15 * time.Second,
			Connect: 3 * time.Second,
			TLS:     7 * time.Second,
			Headers: 8 * time.Second,
		}
		if got != want {
			t.Errorf("BudgetsFrom = %+v, want %+v", got, want)
		}
	})

	t.Run("unset fields fall back to the spec §5 defaults", func(t *testing.T) {
		got := BudgetsFrom(proto.ProbeParams{TlsMs: -1})
		want := Budgets{Budget: DefaultBudget, Connect: DefaultConnect, TLS: DefaultTLS, Headers: DefaultHeaders}
		if got != want {
			t.Errorf("BudgetsFrom = %+v, want %+v", got, want)
		}
	})
}
