// Package sdunits reads systemd's units over D-Bus: ListUnits and the
// manager's change signals.
package sdunits

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

// Timeout bounds connecting and every call: systemd may not answer for a
// while (seen on RHEL 8 and 9 right after the unit was restarted), and the
// recorder must not wait for it.
const Timeout = 10 * time.Second

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

// Open connects within Timeout.
func Open() (*Conn, error) {
	c, err := dial(func() (*dbus.Conn, error) { return dbus.Dial("unix:path=/run/systemd/private") },
		func(c *dbus.Conn) error { return c.Auth([]dbus.Auth{dbus.AuthExternal("0")}) })
	if err == nil {
		return &Conn{c: c, private: true}, nil
	}
	c, err2 := dial(func() (*dbus.Conn, error) { return dbus.SystemBusPrivate() },
		func(c *dbus.Conn) error {
			if err := c.Auth(nil); err != nil {
				return err
			}
			return c.Hello()
		})
	if err2 != nil {
		return nil, fmt.Errorf("systemd: private socket: %v; system bus: %w", err, err2)
	}
	return &Conn{c: c}, nil
}

// dial opens a connection and sets it up (authentication: it waits for the
// other side), closing it when that takes longer than Timeout.
func dial(open func() (*dbus.Conn, error), setup func(*dbus.Conn) error) (*dbus.Conn, error) {
	c, err := open()
	if err != nil {
		return nil, err
	}
	t := time.AfterFunc(Timeout, func() { c.Close() })
	err = setup(c)
	if !t.Stop() {
		return nil, errors.New("no answer within " + Timeout.String())
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// call calls a method with Timeout.
func call(o dbus.BusObject, method string, args ...any) *dbus.Call {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	return o.CallWithContext(ctx, method, 0, args...)
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
	if err := call(c.manager(), "org.freedesktop.systemd1.Manager.ListUnits").Store(&raw); err != nil {
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
			if err := call(c.c.BusObject(), "org.freedesktop.DBus.AddMatch", m).Err; err != nil {
				return nil, fmt.Errorf("systemd AddMatch: %w", err)
			}
		}
	}
	ch := make(chan *dbus.Signal, 1024)
	c.c.Signal(ch)
	if err := call(c.manager(), "org.freedesktop.systemd1.Manager.Subscribe").Err; err != nil {
		c.c.RemoveSignal(ch)
		return nil, fmt.Errorf("systemd Subscribe: %w", err)
	}
	return ch, nil
}
