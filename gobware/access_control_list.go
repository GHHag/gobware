package gobware

import (
	//"net/http"
)

/*type ACL struct {
	ACLMapping []map[string] map[string] map[string] string
}*/

type ACL struct {
	Roles map[string] Role
}

type Role struct {
	Routes map[string] Route
}

type Route struct {
	HttpMethods map[string] HttpMethod
}

type HttpMethod struct {
	HttpVerb map[string] bool
}

func(acl *ACL) NewACLRule(role string, route string, httpMethods []string){
	value, ok := acl.Roles[role]
	if !ok {

	}
	
	for _, httpMethod := range httpMethods {

	}
}

func(acl *ACL) NewACLRole(role string) (Role){
	aclRole, ok := acl.Roles[role]
	if !ok {
		acl.Roles[role] = Role{}
	}

	return aclRole
}

func(acl *ACL) NewACLRoute(role string, route string) (Route){
	aclRoute, ok := acl.Roles[role].Routes[route]
	if !ok {
		acl.Roles[role].Routes[route] = Route{}
	}

	return aclRoute
}

func(acl *ACL) NewACLMethods(role string, route string, httpMethods []string) (HttpMethod){
	var aclMethod HttpMethod
	var ok bool
	for _, httpMethod := range httpMethods {
		aclMethod, ok = acl.Roles[role].Routes[route].HttpMethods[httpMethod]
		if !ok {
			acl.Roles[role].Routes[route].HttpMethods[httpMethod].HttpVerb[httpMethod] = true
		}
	}

	return aclMethod
}

/*func(routeAccess *RouteAccess) CheckAccess() (bool){

	return true
}*/