package gobware

import (
)

type ACL struct {
	Roles map[string] Role
}

type Role struct {
	Routes map[string] Route
}

type Route struct {
	HttpMethods map[string] bool
}

func(acl *ACL) NewACLRule(role string, route string, httpMethods []string) {
	_, ok := acl.Roles[role]
	if !ok {
		acl.NewACLRole(role)
	}

	_, ok = acl.Roles[role].Routes[route]
	if !ok {
		acl.NewACLRoute(role, route)
	}
	
	if !ok {
		acl.NewACLMethods(role, route, httpMethods)
	}
}

func(acl *ACL) NewACLRole(role string) {
	_, ok := acl.Roles[role]
	if !ok {
		acl.Roles[role] = Role{
			Routes: make(map[string] Route),
		}
	}
}

func(acl *ACL) NewACLRoute(role string, route string) {
	_, ok := acl.Roles[role].Routes[route]
	if !ok {
		acl.Roles[role].Routes[route] = Route{
			HttpMethods: make(map[string] bool),
		}
	}
}

func(acl *ACL) NewACLMethods(role string, route string, httpVerbs []string) {
	for _, httpVerb := range httpVerbs {
		_, ok := acl.Roles[role].Routes[route].HttpMethods[httpVerb]
		if !ok {
			acl.Roles[role].Routes[route].HttpMethods[httpVerb] = true
		}
	}
}

/*func(routeAccess *RouteAccess) CheckAccess() (bool){

	return true
}*/