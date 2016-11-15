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
	r_flag               bool
}

func (e *Entity) send() Msg {
	var cj key
	if e.r_flag {
		fmt.Printf("%s \tRatcheting...\n", e.name)
		e.genDH()
		e.rid += 1
		e.j = 0
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.derive(secret)
		e.r_flag = false
	}
	toSend := Msg{e.name, e.rid, e.j, e.our_dh_pub}

	if e.name == "Alice" {
		cj = e.retriveChainkey(e.rid, e.j, true)
	} else {
		cj = e.retriveChainkey(e.rid, e.j, false)
	}

	e.j += 1
	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	fmt.Printf("%s \tour key: %x\n", e.name, cj)
	return toSend
}

func (e *Entity) receive(m Msg) {
	fmt.Printf("%s \treceive: %v\n", e.name, m)
	ck := make([]byte, 64)
	if m.rid == e.rid+1 {
		fmt.Printf("%s \tFollow Ratcheting...\n", e.name)
		e.rid += 1
		e.their_dh = m.dh
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.r_flag = true
		e.derive(secret)
		e.k = 0
	}
	if e.name == "Bob" {
		ck = e.retriveChainkey(m.rid, m.mid, true)
	} else {
		ck = e.retriveChainkey(m.rid, m.mid, false)
	}
	fmt.Printf("%s \ttheir key: %x\n", e.name, ck)
}

func (e *Entity) retriveChainkey(rid, mid int, alice bool) key {
	var ck key
	buf := make([]byte, 64)
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

func (e *Entity) derive(secret [64]byte) {
	r := make([]byte, 64)
	ca := make([]byte, 64)
	cb := make([]byte, 64)
	if len(e.R) > 0 {
		sha3.ShakeSum256(r, append(append(secret[:], e.R[e.rid-1]...), 0))
	} else {
		sha3.ShakeSum256(r, append(secret[:], 0))
	}
	sha3.ShakeSum256(ca, append(secret[:], 1))
	sha3.ShakeSum256(cb, append(secret[:], 2))

	e.R = append(e.R, r)
	e.Ca = append(e.Ca, ca)
	e.Cb = append(e.Cb, cb)
}

func (e *Entity) genDH() {
	c := ed448.NewCurve()
	e.our_dh_priv, e.our_dh_pub, _ = c.GenerateKeys()
	return
}

func main() {
	a, b := initialize()

	b.receive(a.send())
	m1 := a.send()
	m2 := b.send()
	a.receive(m2)
	b.receive(m1)
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
	alice.derive(secret)
	alice.r_flag = true

	bob.name = "Bob"
	bob.derive(secret)
	bob.r_flag = false
	return alice, bob
}
