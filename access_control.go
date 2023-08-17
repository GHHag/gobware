package gobware

type ACL struct {
	roleKey string
	roles map[string] Role
}

type Role struct {
	routes map[string] Route
}

type Route struct {
	httpMethods map[string] bool
}

func NewACL(roleKey string) (*ACL){
	return &ACL{
		roleKey: roleKey,
		roles: make(map[string] Role),
	}
}

// Change order of how ACL is composed to avoid redundant stuff?
func(acl *ACL) AddACLRule(role string, route string, httpMethods []string){
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

func(acl *ACL) addACLRole(role string){
	_, ok := acl.roles[role]
	if !ok {
		acl.roles[role] = Role{
			routes: make(map[string] Route),
		}
	}
}

func(acl *ACL) addACLRoute(role string, route string){
	_, ok := acl.roles[role].routes[route]
	if !ok {
		acl.roles[role].routes[route] = Route{
			httpMethods: make(map[string] bool),
		}
	}
}

func(acl *ACL) addACLMethods(role string, route string, httpMethods []string){
	for _, httpMethod := range httpMethods {
		_, ok := acl.roles[role].routes[route].httpMethods[httpMethod]
		if !ok {
			acl.roles[role].routes[route].httpMethods[httpMethod] = true
		}
	}
}

func(acl *ACL) AddCustomRule(function func(), data interface{}){
	// Allow package users to add custom rules?

	// The ACL type could have a field that stores custom rules as functions
	// that implements some interface.
}

func(acl *ACL) CheckAccess(userData map[string] string, route string, httpMethod string) bool{
	return acl.roles[userData[acl.roleKey]].routes[route].httpMethods[httpMethod]
}