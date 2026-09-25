package admin

import (
	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// hopView is one probed hop of the chain as the admin UI shows it: the
// paths picker offers its path (spec §9.2), the path filter lists it
// (§9.3), and the Settings page's read-only proxy front block names it with
// its role, state and whether it is the active edge (§9.4).
type hopView struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Host   string `json:"host"`
	State  string `json:"state"`
	Path   string `json:"path"`
	Active bool   `json:"active"`
}

// material is the poller's last accepted material, if there is a poller and
// a material at all.
func (h *Handler) material() (panel.Material, bool) {
	if h.deps.Poller == nil {
		return panel.Material{}, false
	}
	return h.deps.Poller.Material()
}

// chainView is what the pages know about the chain from the last GET
// /state (spec §5.1): whether the panel has probed hops, the active edge,
// the probed hops in the panel's order, and the path set the panel serves
// — the path filter's options. Without material it knows nothing: no hops,
// and no paths to filter by.
func chainView(mat panel.Material, have bool) gin.H {
	out := gin.H{"chained": false, "activeEdge": "", "hops": []hopView{}, "served": []string{}}
	if !have {
		return out
	}
	active := mat.Chain.Active()
	hops := []hopView{}
	for _, hop := range mat.Chain.ProbedHops() {
		hops = append(hops, hopView{
			Name: hop.Name, Role: hop.Role, Host: hop.Host, State: hop.State, Path: hop.Path(),
			Active: hop.Role == store.HopRoleEdge && hop.Name == active,
		})
	}
	out["chained"] = mat.Chained()
	out["activeEdge"] = active
	out["hops"] = hops
	out["served"] = mat.Served()
	return out
}

// probesOf is the paths mc probes on mat (spec §5.1's expansion), which is
// what the path filter matches: hops matches every probed hop, a hop by
// name only while the panel probes it. nil without material — then nothing
// is known to match.
func probesOf(mc *store.MonClient, mat panel.Material, have bool) []string {
	if !have {
		return nil
	}
	return registry.ExpandPaths(registry.PathsOf(mc), mat)
}
