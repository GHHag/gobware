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

func NewACL() (*ACL){
	return &ACL{
		Roles: make(map[string] Role),
	}
}

// Change order of how ACL is composed to avoid redundant stuff?
func(acl *ACL) AddACLRule(role string, route string, httpMethods []string){
	_, ok := acl.Roles[role]
	if !ok {
		acl.addACLRole(role)
	}

	_, ok = acl.Roles[role].Routes[route]
	if !ok {
		acl.addACLRoute(role, route)
	}
	
	acl.addACLMethods(role, route, httpMethods)
}

func(acl *ACL) addACLRole(role string){
	_, ok := acl.Roles[role]
	if !ok {
		acl.Roles[role] = Role{
			Routes: make(map[string] Route),
		}
	}
}

func(acl *ACL) addACLRoute(role string, route string){
	_, ok := acl.Roles[role].Routes[route]
	if !ok {
		acl.Roles[role].Routes[route] = Route{
			HttpMethods: make(map[string] bool),
		}
	}
}

func(acl *ACL) addACLMethods(role string, route string, httpMethods []string){
	for _, httpMethod := range httpMethods {
		_, ok := acl.Roles[role].Routes[route].HttpMethods[httpMethod]
		if !ok {
			acl.Roles[role].Routes[route].HttpMethods[httpMethod] = true
		}
	}
}

func(acl *ACL) AddCustomRule(function func(), data interface{}){
	// Allow package users to add custom rules?
}

func(acl *ACL) CheckAccess(role string, route string, httpMethod string) bool{
	return acl.Roles[role].Routes[route].HttpMethods[httpMethod]
}