// Package sdunits reads systemd's units over D-Bus: ListUnits and the
// manager's change signals.
package sdunits

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

// Unit is one loaded unit as org.freedesktop.systemd1.Manager.ListUnits
// returns it.
type Unit struct {
	Name, Description, Load, Active, Sub, Following string
	JobID                                           uint32
	JobType                                         string
}

// Conn is a connection to systemd: its private socket (as systemctl uses
// as root: no D-Bus broker needed), else the system bus.
type Conn struct {
	c       *dbus.Conn
	private bool
}

// Open connects.
func Open() (*Conn, error) {
	c, err := dbus.Dial("unix:path=/run/systemd/private")
	if err == nil {
		if err = c.Auth([]dbus.Auth{dbus.AuthExternal("0")}); err == nil {
			return &Conn{c: c, private: true}, nil
		}
		c.Close()
	}
	c, err2 := dbus.ConnectSystemBus()
	if err2 != nil {
		return nil, fmt.Errorf("systemd: private socket: %v; system bus: %w", err, err2)
	}
	return &Conn{c: c}, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

func (c *Conn) manager() dbus.BusObject {
	return c.c.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
}

// ListUnits returns every loaded unit, in systemd's order.
func (c *Conn) ListUnits() ([]Unit, error) {
	var raw []struct {
		Name, Description, Load, Active, Sub, Following string
		Path                                            dbus.ObjectPath
		JobID                                           uint32
		JobType                                         string
		JobPath                                         dbus.ObjectPath
	}
	if err := c.manager().Call("org.freedesktop.systemd1.Manager.ListUnits", 0).Store(&raw); err != nil {
		return nil, fmt.Errorf("systemd ListUnits: %w", err)
	}
	out := make([]Unit, len(raw))
	for i, r := range raw {
		out[i] = Unit{Name: r.Name, Description: r.Description, Load: r.Load, Active: r.Active, Sub: r.Sub,
			Following: r.Following, JobID: r.JobID, JobType: r.JobType}
	}
	return out, nil
}

// Subscribe asks systemd for its change signals and returns them: any
// signal means a unit or job changed.
func (c *Conn) Subscribe() (<-chan *dbus.Signal, error) {
	if !c.private {
		for _, m := range []string{
			"type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.systemd1.Manager'",
			"type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'",
		} {
			if err := c.c.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, m).Err; err != nil {
				return nil, fmt.Errorf("systemd AddMatch: %w", err)
			}
		}
	}
	ch := make(chan *dbus.Signal, 1024)
	c.c.Signal(ch)
	if err := c.manager().Call("org.freedesktop.systemd1.Manager.Subscribe", 0).Err; err != nil {
		c.c.RemoveSignal(ch)
		return nil, fmt.Errorf("systemd Subscribe: %w", err)
	}
	return ch, nil
}
