// Package ldap autentica usuarios contra OpenLDAP con search-then-bind:
// la cuenta de servicio busca el DN del usuario y luego se hace bind con su contraseña.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// ErrInvalidCredentials no distingue entre usuario inexistente y contraseña errónea.
var ErrInvalidCredentials = errors.New("credenciales inválidas")

type Identity struct {
	Username string
	Name     string
	Email    string
	Groups   []string
}

type Config struct {
	URL          string
	BindDN       string
	BindPassword string
	UsersDN      string
	GroupsDN     string
	StartTLS     bool
	Timeout      time.Duration
}

type Client struct{ cfg Config }

func New(cfg Config) *Client { return &Client{cfg: cfg} }

func (c *Client) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	// Una contraseña vacía sería un "unauthenticated bind", que el servidor puede aceptar.
	if username == "" || password == "" {
		return Identity{}, ErrInvalidCredentials
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = conn.Close() }()

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return Identity{}, fmt.Errorf("ldap: bind de la cuenta de servicio: %w", err)
	}
	entry, err := c.findUser(conn, username)
	if err != nil {
		return Identity{}, err
	}
	// Los grupos se leen como cuenta de servicio (el usuario no tiene acceso a ou=groups).
	groups, err := c.groupsOf(conn, entry.DN)
	if err != nil {
		return Identity{}, err
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return Identity{}, ErrInvalidCredentials
		}
		return Identity{}, fmt.Errorf("ldap: bind del usuario: %w", err)
	}
	return Identity{
		Username: entry.GetAttributeValue("uid"),
		Name:     entry.GetAttributeValue("cn"),
		Email:    entry.GetAttributeValue("mail"),
		Groups:   groups,
	}, nil
}

func (c *Client) dial(ctx context.Context) (*goldap.Conn, error) {
	timeout := c.cfg.Timeout
	if d, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(d))
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	conn, err := goldap.DialURL(c.cfg.URL, goldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, fmt.Errorf("ldap: conexión: %w", err)
	}
	conn.SetTimeout(timeout)
	if c.cfg.StartTLS {
		u, err := url.Parse(c.cfg.URL)
		if err == nil {
			err = conn.StartTLS(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		}
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	return conn, nil
}

func (c *Client) findUser(conn *goldap.Conn, username string) (*goldap.Entry, error) {
	req := goldap.NewSearchRequest(
		c.cfg.UsersDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, 0, false, // sizeLimit 2: basta para detectar un uid ambiguo
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", goldap.EscapeFilter(username)),
		[]string{"uid", "cn", "mail"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("ldap: búsqueda del usuario: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrInvalidCredentials
	}
	return res.Entries[0], nil
}

func (c *Client) groupsOf(conn *goldap.Conn, userDN string) ([]string, error) {
	req := goldap.NewSearchRequest(
		c.cfg.GroupsDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", goldap.EscapeFilter(userDN)),
		[]string{"cn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: búsqueda de grupos: %w", err)
	}
	groups := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		groups = append(groups, e.GetAttributeValue("cn"))
	}
	return groups, nil
}
