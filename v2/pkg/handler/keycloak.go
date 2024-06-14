package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/Nerzal/gocloak/v13"
	"github.com/glauth/glauth/v2/internal/monitoring"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/glauth/ldap"
)

const (
	BIND_DN_TYPE_CLIENT = "client"
	BIND_DN_TYPE_USER   = "user"

	CLIENT_BIND_CN = "readonly"
)

type keycloakSession struct {
	clientID     string
	clientSecret string
}

type keycloakHandler struct {
	backend  config.Backend
	log      *zerolog.Logger
	sessions map[string]keycloakSession
	lock     *sync.Mutex

	monitor monitoring.MonitorInterface
	tracer  trace.Tracer
}

// global lock for keycloakHandler sessions & servers manipulation
var keycloakLock sync.Mutex

func NewKeycloakHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	return keycloakHandler{
		backend:  options.Backend,
		log:      options.Logger,
		sessions: make(map[string]keycloakSession),
		lock:     &keycloakLock,

		monitor: options.Monitor,
		tracer:  options.Tracer,
	}
}

func (h keycloakHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (result ldap.LDAPResultCode, err error) {

	// parse client_id or username from bindDN
	entryName, bindType, err := h.parseBindDN(bindDN)
	if err != nil {
		h.log.Warn().Str("binddn", bindDN).Str("basedn", h.backend.BaseDN).AnErr("error: ", err)
		return ldap.LDAPResultInvalidCredentials, nil
	}

	kcHostname := h.backend.Servers[0]
	kcRealm := h.backend.Realm

	ctx := context.Background()
	kcClient := gocloak.NewClient(kcHostname)

	if bindType == BIND_DN_TYPE_CLIENT {
		token, err := kcClient.LoginClient(ctx, entryName, bindSimplePw, kcRealm)
		if err != nil {
			return ldap.LDAPResultInvalidCredentials, nil
		}
		h.log.Debug().Str("client", token.AccessToken).Err(err).Msg("client login pat")

		id := connID(conn)
		s := keycloakSession{
			clientID:     entryName,
			clientSecret: bindSimplePw,
		}
		h.lock.Lock()
		h.sessions[id] = s
		h.lock.Unlock()

		stats.Frontend.Add("bind_successes", 1)

	} else if bindType == BIND_DN_TYPE_USER {

		// OAuth2 "Direct Access Grants"
		session, exists := h.getSession(conn)
		if !exists {
			return ldap.LDAPResultInvalidCredentials, nil
		}

		clientID := session.clientID
		clientSecret := session.clientSecret

		token, err := kcClient.Login(ctx, clientID, clientSecret, kcRealm, entryName, bindSimplePw)
		if err != nil {
			return ldap.LDAPResultInvalidCredentials, nil
		}
		h.log.Debug().Str("client", token.AccessToken).Err(err).Msg("Direct Access Grants")

	} else {
		return ldap.LDAPResultInvalidCredentials, nil
	}

	return ldap.LDAPResultSuccess, nil
}

func (h keycloakHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (result ldap.ServerSearchResult, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "search", "status": fmt.Sprintf("%v", result.ResultCode)},
			time.Since(start).Seconds(),
		)
	}()

	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.Debug().Str("binddn", bindDN).Str("basedn", baseDN).Str("src", conn.RemoteAddr().String()).Str("filter", searchReq.Filter).Msg("Search request")
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: BindDN %s not in our BaseDN %s", bindDN, h.backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.backend.BaseDN)
	}

	session, exists := h.getSession(conn)
	if !exists {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: BindDN not allowed %s", bindDN)
	}

	h.log.Debug().Str("binddn", bindDN).Str("basedn", baseDN).Str("filter", searchReq.Filter).Msg("Search request")

	f, err := ldap.CompileFilter(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
	}

	username, err := h.parseFilterUserName(f)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	h.log.Debug().Str("filterEntity:", username).Msg("Search request")

	// memberOf

	clientID := h.backend.ClientID
	clientSecret := h.backend.ClientSecret
	kcHostname := h.backend.Servers[0]
	kcRealm := h.backend.Realm

	bindClientID := session.clientID

	ctx := context.Background()
	kcClient := gocloak.NewClient(kcHostname)

	token, err := kcClient.LoginClient(ctx, clientID, clientSecret, kcRealm)
	if err != nil {
		panic("Login failed:" + err.Error())
	}

	clients, err := kcClient.GetClients(ctx, token.AccessToken, kcRealm, gocloak.GetClientsParams{
		ClientID: &bindClientID,
	})
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	clientUUID := *clients[0].ID

	exact := true
	users, err := kcClient.GetUsers(
		ctx,
		token.AccessToken,
		kcRealm,
		gocloak.GetUsersParams{
			Username: &username,
			Exact:    &exact,
		},
	)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	if len(users) != 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultNoSuchObject}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}

	user := users[0]
	userUUID := user.ID

	roleMappings, err := kcClient.GetRoleMappingByUserID(ctx, token.AccessToken, kcRealm, *userUUID)
	h.log.Debug().Str("user", roleMappings.String()).Err(err).Msg("Could not get user")

	roles, err := kcClient.GetCompositeClientRolesByUserID(ctx, token.AccessToken, kcRealm, clientUUID, *userUUID)
	if err != nil {
		panic("Login failed:" + err.Error())
	}

	memberOfs := []string{}
	for _, role := range roles {
		a := fmt.Sprintf("cn=%s,ou=%s,ou=clients,%s", *role.Name, bindClientID, h.backend.BaseDN)
		memberOfs = append(memberOfs, a)
	}

	entries := []*ldap.Entry{}

	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{*user.Username}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{*user.FirstName}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "sn", Values: []string{*user.LastName}})
	//attrs = append(attrs, &ldap.EntryAttribute{Name: "displayName", Values: []string{*user.LastName + ", " + *user.FirstName}})
	//attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{"bob"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{*user.Email}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: memberOfs})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"inetOrgPerson", "uidObject"}})

	dn := fmt.Sprintf("%s=%s,ou=users,%s", h.backend.NameFormat, username, h.backend.BaseDN)
	h.log.Debug().Str("dn:", dn).Msg("Search request")

	entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})

	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

func (h keycloakHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

// Add is not yet supported for the keycloak backend
func (h keycloakHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "add", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the keycloak backend
func (h keycloakHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "modify", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the keycloak backend
func (h keycloakHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	_, span := h.tracer.Start(context.Background(), "handler.keycloakHandler.Delete")
	defer span.End()

	start := time.Now()
	defer func() {
		h.monitor.SetResponseTimeMetric(
			map[string]string{"operation": "delete", "status": fmt.Sprintf("%v", result)},
			time.Since(start).Seconds(),
		)
	}()
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// FindUser with the given username. Optional
func (h keycloakHandler) FindUser(ctx context.Context, userName string, searchByUPN bool) (found bool, user config.User, err error) {
	_, span := h.tracer.Start(ctx, "handler.keycloakHandler.FindUser")
	defer span.End()

	return false, config.User{}, nil
}

func (h keycloakHandler) FindGroup(ctx context.Context, groupName string) (found bool, group config.Group, err error) {
	_, span := h.tracer.Start(ctx, "handler.keycloakHandler.FindGroup")
	defer span.End()

	return false, config.Group{}, nil
}

func (h keycloakHandler) parseFilterUserName(f *ber.Packet) (string, error) {
	userName := ""
	switch f.Tag {
	case ldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return "", errors.New("Equality match must have only two children")
		}
		attribute := strings.ToLower(f.Children[0].Value.(string))
		value := f.Children[1].Value.(string)
		if attribute == h.backend.NameFormat {
			userName = strings.ToLower(value)
		}
	case ldap.FilterAnd:
		for _, child := range f.Children {
			subType, err := h.parseFilterUserName(child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				userName = subType
			}
		}
	case ldap.FilterOr:
		for _, child := range f.Children {
			subType, err := h.parseFilterUserName(child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				userName = subType
			}
		}
	}
	return strings.ToLower(userName), nil
}

// cn=readonly,ou={clientID},ou=clients,dc={realm},dc=example,dc=com
// cn={username},ou=users,dc={realm},dc=example,dc=com
func (h keycloakHandler) parseBindDN(bindDN string) (string, string, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		return "", "", errors.New("BindDN not part of our BaseDN")
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	if len(parts) == 3 {
		constCN := strings.TrimPrefix(parts[0], "cn=")
		clientID := strings.TrimPrefix(parts[1], "ou=")
		group := strings.TrimPrefix(parts[2], "ou=")

		if CLIENT_BIND_CN == constCN && group == "clients" {
			return clientID, BIND_DN_TYPE_CLIENT, nil
		}
		return "", "", errors.New("invalid client bindDN")
	}

	if len(parts) == 2 {
		userName := strings.TrimPrefix(parts[0], h.backend.NameFormat+"=")
		group := strings.TrimPrefix(parts[1], "ou=")
		if group == "users" {
			return userName, BIND_DN_TYPE_USER, nil
		}
		return "", "", errors.New("invalid user bindDN")
	}

	return "", "", errors.New("could not parse bindDN")
}

func (h keycloakHandler) getSession(conn net.Conn) (keycloakSession, bool) {
	h.lock.Lock()
	id := connID(conn)
	session, ok := h.sessions[id]
	h.lock.Unlock()

	return session, ok
}
