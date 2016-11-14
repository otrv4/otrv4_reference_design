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
	Ca, Cb               [][]key
	rid, j, k            int
	r_flag               bool
}

func (e *Entity) send() Msg {
	cj := make([]byte, 64)
	if e.r_flag {
		fmt.Printf("%s \tRatcheting...\n", e.name)
		e.genDH()
		e.rid += 1
		e.j = 0
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.derive(secret)
		e.r_flag = false
	} else {
		if e.name == "Alice" {
			sha3.ShakeSum256(cj, e.Ca[e.rid][e.j-1])
			e.Ca[e.rid] = append(e.Ca[e.rid], cj)
		} else {
			sha3.ShakeSum256(cj, e.Cb[e.rid][e.j-1])
			e.Cb[e.rid] = append(e.Cb[e.rid], cj)
		}
	}
	toSend := Msg{e.name, e.rid, e.j, e.our_dh_pub}

	if e.name == "Alice" {
		cj = e.Ca[e.rid][e.j]
	} else {
		cj = e.Cb[e.rid][e.j]
	}

	e.j += 1
	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	fmt.Printf("%s \tkey: %x\n", e.name, cj)
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
	} else {
		if e.name == "Bob" {
			sha3.ShakeSum256(ck, e.Ca[e.rid][e.k])
			e.Ca[e.rid] = append(e.Ca[e.rid], ck)
		} else {
			sha3.ShakeSum256(ck, e.Cb[e.rid][e.k])
			e.Cb[e.rid] = append(e.Cb[e.rid], ck)
		}
		e.k += 1
	}

	if e.name == "Bob" {
		ck = e.Ca[e.rid][e.k]
	} else {
		ck = e.Cb[e.rid][e.k]
	}
	fmt.Printf("%s \tkey: %x\n", e.name, ck)
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
	e.Ca = append(e.Ca, []key{ca})
	e.Cb = append(e.Cb, []key{cb})
}

func (e *Entity) genDH() {
	c := ed448.NewCurve()
	e.our_dh_priv, e.our_dh_pub, _ = c.GenerateKeys()
	return
}

func main() {
	a, b := initialize()

	b.receive(a.send())
	b.receive(a.send())
	b.receive(a.send())
	a.receive(b.send())
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
