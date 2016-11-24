package main

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/twstrike/ed448"
)

const (
	Q = iota
	P1
	P2
	D
)

type Msg struct {
	mtype    int
	sender   string
	rid, mid int
	dh       pubkey

	encKey key // this is here only to check if we can decrypt
}

func (m Msg) decryptWith(k key) {
	if !bytes.Equal(k, m.encKey) {
		panic("failed to decrypt message.")
	}
}

var c = ed448.NewCurve()
var NULLSEC = seckey{}
var NULLPUB = pubkey{}

type seckey [144]byte
type pubkey [56]byte
type key []byte

type AuthState int

const (
	AUTHSTATE_NONE AuthState = iota
	AUTHSTATE_AWAITING_DRE_AUTH
)

type Entity struct {
	name                          string
	our_dh_pub, their_dh          pubkey
	our_dh_priv, our_prev_dh_priv seckey
	R                             []key
	Ca, Cb                        []key
	rid, j, k                     int

	AuthState
}

func (e *Entity) sendData() Msg {
	var cj key
	if e.j == 0 {
		fmt.Println()
		fmt.Printf("%s \tRatcheting...\n", e.name)
		copy(e.our_prev_dh_priv[:], e.our_dh_priv[:])
		e.our_dh_priv, e.our_dh_pub, _ = c.GenerateKeys()
		e.rid += 1
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.derive(secret[:])
	}

	cj = e.retriveChainkey(e.rid, e.j)
	toSend := Msg{D, e.name, e.rid, e.j, e.our_dh_pub, cj}
	e.j += 1

	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	fmt.Printf("%s \tour key: %x\n", e.name, cj)
	return toSend
}

func (e *Entity) receive(m Msg) {
	fmt.Println()
	fmt.Printf("%s \treceive: %v\n", e.name, m)
	switch m.mtype {
	case D:
		e.receiveData(m)
		break
	case Q:
		break
	case P1:
		e.receiveP1(m)
		break
	case P2:
		e.receiveP2(m)
		break
	}
}

func (e *Entity) transitionDAKE() bool {
	return e.rid > 0
}

func (e *Entity) sendP1() Msg {
	copy(e.our_prev_dh_priv[:], e.our_dh_priv[:])
	e.our_dh_priv, e.our_dh_pub, _ = c.GenerateKeys()

	if e.transitionDAKE() {
		fmt.Println("Sending a P1 to transition to a new DAKE")

		// We want:
		// 1 - Bob to decrypt messages Alice sent before he generated P1.
		// 2 - Bob to decrypt messages Alice send after rec. P1 (and send. P2).
		// 3 - Bob to send messages after sending P1, and Alice to decrypt them.
		// 4 - Alice to send messages after rec. P1 (and send. P2).
		//     Why would not it work?

		// For 1 and 2:
		// If Alice sends a new follow up message:
		// - Bob is already in that ratchet.
		// - He can decrypt by using the previous Chain Key (available)
		// If Alice sends a message on a NEW ratchet:
		// - Bob will see her new DH pub, but which of his DH pub to use?
		//	- If she HAS received his P1:
		//	  - Use our_dh_priv (same as what's in P1) and their_dh (from the msg).
		//	    Since nothing happens between receiving P1 and sending P2, and Alice
		//	    always start a NEW ratchet on the first message after the DAKE,
		//	    their_dh won't be from P2.
		//		  Alice's DH from P2 is a waste, but it does not break. FINE!
		//		- We can identify this because we will have received P2 before this
		//		  data msg. DOUBLE FINE!
		//    - This is how it behaves before. TRIPLE FINE! DONE!
		//	- If she HAS NOT received his P1, but was ready to a NEW ratchet:
		//	  - Use our_prev_dh_priv (from before P1) and their_dh (from the msg).
		//    - We can identify this also: it is every time we receive a data msg
		//      while we are in WAITING_DRE_AUTH. FINE! DONE!
	}

	toSend := Msg{P1, e.name, -1, -1, e.our_dh_pub, nil}
	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	e.AuthState = AUTHSTATE_AWAITING_DRE_AUTH
	return toSend
}

func (e *Entity) receiveP1(m Msg) {
	e.their_dh = m.dh

	if e.transitionDAKE() {
		fmt.Println("Receiving a P1 to transition to a new DAKE")
		//Nothing happens between this and sendP2, so no need to worry. FINE!
	}
}

func (e *Entity) sendP2() Msg {
	copy(e.our_prev_dh_priv[:], e.our_dh_priv[:])
	e.our_dh_priv, e.our_dh_pub, _ = c.GenerateKeys()
	secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
	e.derive(secret[:])
	e.j = 0 // she will ratchet when sending next

	if e.transitionDAKE() {
		fmt.Println("Sending a P2 to transition to a new DAKE")

		// We want:
		// 1 - Alice to decrypt messages Bob sent after generating P1, but she
		//     receives after sending P2. Bob has NOT received P2 yet.
		// 2 - Alice to decrypt messages Bob sent after rec. P2. Fine!

		// For 1 (same as case 3 in sendP1): TODO: elaborate on this. It's late!
	}

	toSend := Msg{P2, e.name, -1, -1, e.our_dh_pub, nil}
	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	e.AuthState = AUTHSTATE_NONE
	return toSend
}

func (e *Entity) receiveP2(m Msg) {
	e.their_dh = m.dh
	secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
	e.derive(secret[:])

	e.j = 1 // so he does not ratchet

	if e.transitionDAKE() {
		fmt.Println("Receiving a P2 to transition to a new DAKE")
	}

	e.AuthState = AUTHSTATE_NONE
}

func (e *Entity) receiveData(m Msg) {
	ck := make([]byte, 64)
	if m.rid == e.rid+1 {
		fmt.Printf("%s \tFollow Ratcheting...\n", e.name)

		e.rid = m.rid
		e.their_dh = m.dh
		secret := c.ComputeSecret(e.our_dh_priv, e.their_dh)
		e.derive(secret[:])
		e.j = 0 // need to ratchet next time when send
	} else if e.k > m.mid {
		//panic("we received a message delayed out of order")
	}

	e.k = m.mid
	ck = e.retriveChainkey(m.rid, m.mid)
	fmt.Printf("%s \ttheir key: %x\n", e.name, ck)

	m.decryptWith(ck)
}

func (e *Entity) wasAliceAt(rid int) bool {
	return rid%2 == 1
}

func (e *Entity) retriveChainkey(rid, mid int) key {
	var ck key
	buf := make([]byte, 64)

	if e.wasAliceAt(rid) {
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

func (e *Entity) query() Msg {
	toSend := Msg{mtype: Q, sender: e.name}
	fmt.Printf("%s \tsending: %v\n", e.name, toSend)
	return toSend
}

func main() {
	a, b := initialize()
	b.receive(a.query())
	a.receive(b.sendP1())
	b.receive(a.sendP2())

	fmt.Println("=========================")
	fmt.Println("Testing sync data message")
	fmt.Println("=========================")

	a.receive(b.sendData()) // b sends first, so no new ratchet happens.
	a.receive(b.sendData()) // b again: this is another follow up msg.
	b.receive(a.sendData()) // a sends, a new ratchet happens and bob follows.
	b.receive(a.sendData()) // a again: this is a follow up.

	fmt.Println("=========================")
	fmt.Println("Testing async data message")
	fmt.Println("=========================")

	m1 := a.sendData() // a sends again: another follow up message.
	m2 := b.sendData() // b sends now, a new ratcher happens for bob.
	m3 := a.sendData() // a sends again: another follow up message.

	b.receive(m1) // b receives follow up message from a previous ratchet.
	b.receive(m3) // b receives follow up message from a previous ratchet.
	a.receive(m2) // a receives a message from a new ratchet. She follows the ratchet.

	fmt.Println("=========================")
	fmt.Println("Testing new sync DAKE")
	fmt.Println("=========================")

	b.receive(a.query())
	a.receive(b.sendP1())
	b.receive(a.sendP2())

	b.receive(a.sendData()) // a sends, a new ratchet starts and bob follows
	b.receive(a.sendData()) // a sends a follow up
	a.receive(b.sendData()) // b sends, a new ratchet starts and alice follows
	a.receive(b.sendData()) // b sends a follow up

	fmt.Println("=========================")
	fmt.Println("Testing async DAKE message")
	fmt.Println("=========================")

	b.receive(a.query())
	p1 := b.sendP1()
	b0 := b.sendData() // bob sends a data message during a new DAKE, is this a follow up msg?
	b1 := b.sendData() // bob sends a data message during a new DAKE - surely a follow up msg.

	b.receive(a.sendData()) // a sends a new message before she receives p1, but after bob sends p1.
	// this will be a new ratchet, and thats a problem because bob will also ratchet when sending p1.

	a.receive(p1)      // a receives p1
	p2 := a.sendP2()   // ... and immediately replies with a p2
	a0 := a.sendData() // ... and send a new data msg

	b.receive(p2) // bob receives a p2
	b.receive(a0) // and the a0

	a.receive(b0) // a receives b0 (I want to see how it works if she receives this BEFORE sending a0)
	a.receive(b1) // a receives b1
}

func initialize() (alice, bob Entity) {
	alice.name = "Alice"
	alice.rid = 0
	bob.name = "Bob"
	bob.rid = 0

	return alice, bob
}
