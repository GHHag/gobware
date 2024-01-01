package gobware

type acl struct {
	roleKey string
	roles   map[string]role
}

type role struct {
	routes map[string]route
}

type route struct {
	httpMethods map[string]bool
}

func NewACL(roleKey string) *acl {
	return &acl{
		roleKey: roleKey,
		roles:   make(map[string]role),
	}
}

func (acl *acl) AddACLRule(role string, route string, httpMethods []string) {
	_, ok := acl.roles[role]
	if !ok {
		acl.addACLRole(role)
	}

	_, ok = acl.roles[role].routes[route]
	if !ok {
		acl.addACLRoute(role, route)
	}

	acl.addACLMethods(role, route, httpMethods)
}

func (acl *acl) addACLRole(roleStr string) {
	_, ok := acl.roles[roleStr]
	if !ok {
		acl.roles[roleStr] = role{
			routes: make(map[string]route),
		}
	}
}

func (acl *acl) addACLRoute(role string, routeStr string) {
	_, ok := acl.roles[role].routes[routeStr]
	if !ok {
		acl.roles[role].routes[routeStr] = route{
			httpMethods: make(map[string]bool),
		}
	}
}

func (acl *acl) addACLMethods(role string, route string, httpMethods []string) {
	for _, httpMethod := range httpMethods {
		_, ok := acl.roles[role].routes[route].httpMethods[httpMethod]
		if !ok {
			acl.roles[role].routes[route].httpMethods[httpMethod] = true
		}
	}
}

func (acl *acl) AddCustomRule(function func(), data interface{}) {
	// Allow package users to add custom rules?

	// The ACL type could have a field that stores custom rules as functions
	// that implements some interface.
}

func (acl *acl) CheckAccess(userData map[string]string, route string, httpMethod string) bool {
	return acl.roles[userData[acl.roleKey]].routes[route].httpMethods[httpMethod]
}
