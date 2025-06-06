package rbacpolicy

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	applister "github.com/argoproj/argo-cd/v3/pkg/client/listers/application/v1alpha1"
	jwtutil "github.com/argoproj/argo-cd/v3/util/jwt"
	"github.com/argoproj/argo-cd/v3/util/rbac"
)

// RBACPolicyEnforcer provides an RBAC Claims Enforcer which additionally consults AppProject
// roles, jwt tokens, and groups. It is backed by a AppProject informer/lister cache and does not
// make any API calls during enforcement.
type RBACPolicyEnforcer struct {
	enf        *rbac.Enforcer
	projLister applister.AppProjectNamespaceLister
	scopes     []string
}

// NewRBACPolicyEnforcer returns a new RBAC Enforcer for the Argo CD API Server
func NewRBACPolicyEnforcer(enf *rbac.Enforcer, projLister applister.AppProjectNamespaceLister) *RBACPolicyEnforcer {
	return &RBACPolicyEnforcer{
		enf:        enf,
		projLister: projLister,
		scopes:     nil,
	}
}

func (p *RBACPolicyEnforcer) SetScopes(scopes []string) {
	p.scopes = scopes
}

func (p *RBACPolicyEnforcer) GetScopes() []string {
	scopes := p.scopes
	if scopes == nil {
		scopes = rbac.DefaultScopes
	}
	return scopes
}

func IsProjectSubject(subject string) bool {
	_, _, ok := GetProjectRoleFromSubject(subject)
	return ok
}

func GetProjectRoleFromSubject(subject string) (string, string, bool) {
	parts := strings.Split(subject, ":")
	if len(parts) == 3 && parts[0] == "proj" {
		return parts[1], parts[2], true
	}
	return "", "", false
}

// EnforceClaims is an RBAC claims enforcer specific to the Argo CD API server
func (p *RBACPolicyEnforcer) EnforceClaims(claims jwt.Claims, rvals ...any) bool {
	mapClaims, err := jwtutil.MapClaims(claims)
	if err != nil {
		return false
	}

	subject := jwtutil.GetUserIdentifier(mapClaims)
	// Check if the request is for an application resource. We have special enforcement which takes
	// into consideration the project's token and group bindings
	var runtimePolicy string
	var projName string
	proj := p.getProjectFromRequest(rvals...)
	if proj != nil {
		if IsProjectSubject(subject) {
			return p.enforceProjectToken(subject, proj, rvals...)
		}
		runtimePolicy = proj.ProjectPoliciesString()
		projName = proj.Name
	}

	// NOTE: This calls prevent multiple creation of the wrapped enforcer
	enforcer := p.enf.CreateEnforcerWithRuntimePolicy(projName, runtimePolicy)

	// Check the subject. This is typically the 'admin' case.
	// NOTE: the call to EnforceWithCustomEnforcer will also consider the default role
	vals := append([]any{subject}, rvals[1:]...)
	if p.enf.EnforceWithCustomEnforcer(enforcer, vals...) {
		return true
	}

	scopes := p.scopes
	if scopes == nil {
		scopes = rbac.DefaultScopes
	}
	// Finally check if any of the user's groups grant them permissions
	groups := jwtutil.GetScopeValues(mapClaims, scopes)

	// Get groups to reduce the amount to checking groups
	groupingPolicies, err := enforcer.GetGroupingPolicy()
	if err != nil {
		log.WithError(err).Error("failed to get grouping policy")
		return false
	}
	for gidx := range groups {
		for gpidx := range groupingPolicies {
			// Prefilter user groups by groups defined in the model
			if groupingPolicies[gpidx][0] == groups[gidx] {
				vals := append([]any{groups[gidx]}, rvals[1:]...)
				if p.enf.EnforceWithCustomEnforcer(enforcer, vals...) {
					return true
				}
				break
			}
		}
	}
	logCtx := log.WithFields(log.Fields{"claims": claims, "rval": rvals, "subject": subject, "groups": groups, "project": projName, "scopes": scopes})
	logCtx.Debug("enforce failed")
	return false
}

// getProjectFromRequest parses the project name from the RBAC request and returns the associated
// project (if it exists)
func (p *RBACPolicyEnforcer) getProjectFromRequest(rvals ...any) *v1alpha1.AppProject {
	if len(rvals) != 4 {
		return nil
	}
	getProjectByName := func(projName string) *v1alpha1.AppProject {
		proj, err := p.projLister.Get(projName)
		if err != nil {
			return nil
		}
		return proj
	}
	if res, ok := rvals[1].(string); ok {
		if obj, ok := rvals[3].(string); ok {
			switch res {
			case rbac.ResourceApplications, rbac.ResourceRepositories, rbac.ResourceClusters, rbac.ResourceLogs, rbac.ResourceExec:
				if objSplit := strings.Split(obj, "/"); len(objSplit) >= 2 {
					return getProjectByName(objSplit[0])
				}
			case rbac.ResourceProjects:
				// we also automatically give project tokens and groups 'get' access to the project
				return getProjectByName(obj)
			}
		}
	}
	return nil
}

// enforceProjectToken will check to see the valid token has not yet been revoked in the project
func (p *RBACPolicyEnforcer) enforceProjectToken(subject string, proj *v1alpha1.AppProject, rvals ...any) bool {
	subjectSplit := strings.Split(subject, ":")
	if len(subjectSplit) != 3 {
		return false
	}
	projName, _ := subjectSplit[1], subjectSplit[2]
	if projName != proj.Name {
		// this should never happen (we generated a project token for a different project)
		return false
	}

	vals := append([]any{subject}, rvals[1:]...)
	return p.enf.EnforceRuntimePolicy(proj.Name, proj.ProjectPoliciesString(), vals...)
}
