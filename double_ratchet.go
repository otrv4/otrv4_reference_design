package main

import (
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

type Msg struct {
	sender   string
	rid, mid int
	dh       pubkey
}

var c = ed448.NewCurve()

type seckey [144]byte
type pubkey [56]byte
type key []byte

type Entity struct {
	name                 string
	our_dh_pub, their_dh pubkey
	our_dh_priv          seckey
	R                    []key
	Ca, Cb               []key
	rid, j, k            int
	initiator            bool
}

func (e *Entity) send() Msg {
	var cj key
	if e.j == 0 && !(e.rid == 0 && !e.initiator) {
		fmt.Println()
		fmt.Printf("%s \tRatcheting...\n", e.name)
		e.our_dh_priv, e.our_dh_pub, _ = c.GenerateKeys()
		e.rid += 1
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.derive(secret[:])
	}
	toSend := Msg{e.name, e.rid, e.j, e.our_dh_pub}
	cj = e.retriveChainkey(e.rid, e.j)
	e.j += 1
	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	fmt.Printf("%s \tour key: %x\n", e.name, cj)
	return toSend
}

func (e *Entity) receive(m Msg) {
	fmt.Println()
	fmt.Printf("%s \treceive: %v\n", e.name, m)
	ck := make([]byte, 64)
	if m.rid == e.rid+1 {
		fmt.Printf("%s \tFollow Ratcheting...\n", e.name)
		e.rid = m.rid
		e.their_dh = m.dh
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.derive(secret[:])
		e.j = 0 // need to ratchet next time when send
	} else if m.rid != e.rid && m.rid != e.rid-1 {
		panic("we received a message skip a ratchet")
	} else if e.k > m.mid {
		panic("we received a message delayed out of order")
	}
	e.k = m.mid
	ck = e.retriveChainkey(m.rid, m.mid)
	fmt.Printf("%s \ttheir key: %x\n", e.name, ck)
}

func (e *Entity) retriveChainkey(rid, mid int) key {
	var ck key
	buf := make([]byte, 64)
	alice := rid%2 == 1
	if alice {
		ck = e.Ca[rid]
	} else {
		ck = e.Cb[rid]
	}
	copy(buf, ck)
	for i := mid; i > 0; i-- {
		sha3.ShakeSum256(buf, buf)
	}
	return buf
}

func (e *Entity) derive(secret []byte) {
	r := make([]byte, 64)
	ca := make([]byte, 64)
	cb := make([]byte, 64)
	if len(e.R) > 0 {
		secret = append(secret, e.R[e.rid-1]...)
	}
	sha3.ShakeSum256(r, append(secret, 0))
	sha3.ShakeSum256(ca, append(secret, 1))
	sha3.ShakeSum256(cb, append(secret, 2))

	e.R = append(e.R, r)
	e.Ca = append(e.Ca, ca)
	e.Cb = append(e.Cb, cb)
}

func main() {
	a, b := initialize()

	a.receive(b.send())
	b.receive(a.send())
	m1 := a.send()
	m2 := b.send()
	m3 := a.send()
	b.receive(m1)
	a.receive(m2)
	b.receive(m3)
	a.receive(b.send())
	b.receive(a.send())
}

func initialize() (alice, bob Entity) {
	alice.our_dh_priv, alice.our_dh_pub, _ = c.GenerateKeys()
	bob.our_dh_priv, bob.our_dh_pub, _ = c.GenerateKeys()

	alice.their_dh = bob.our_dh_pub
	bob.their_dh = alice.our_dh_pub

	secret := c.ComputeSecret(alice.our_dh_priv, alice.their_dh)

	alice.name = "Alice"
	alice.initiator = true
	alice.derive(secret[:])

	bob.name = "Bob"
	bob.initiator = false
	bob.derive(secret[:])

	return alice, bob
}
