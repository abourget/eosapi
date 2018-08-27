package p2p

import (
	"fmt"
	"io"
	"net"
	"time"

	"math"

	"runtime"

	"bufio"

	"github.com/eoscanada/eos-go"
	"github.com/eoscanada/eos-go/ecc"
)

type Peer struct {
	Address       string
	chainID       eos.SHA256Bytes
	agent         string
	connection    net.Conn
	reader        io.Reader
	handshake     eos.HandshakeMessage
	catchup       Catchup
	listener      bool
	mockHandshake bool
}

type HandshakeInfo struct {
	HeadBlockNum             uint32
	HeadBlockID              eos.SHA256Bytes
	HeadBlockTime            time.Time
	LastIrreversibleBlockNum uint32
	LastIrreversibleBlockID  eos.SHA256Bytes
}

func newPeer(address string, chainID eos.SHA256Bytes, agent string, listener bool, mockHandshake bool) *Peer {

	return &Peer{
		Address:       address,
		chainID:       chainID,
		agent:         agent,
		listener:      listener,
		mockHandshake: mockHandshake,
	}
}

func NewIncommingPeer(address string, chainID eos.SHA256Bytes, agent string) *Peer {
	return newPeer(address, chainID, agent, true, false)
}

func NewOutgoingPeer(address string, chainID eos.SHA256Bytes, agent string, mockHandshake bool) *Peer {
	return newPeer(address, chainID, agent, false, mockHandshake)
}

func (p *Peer) Read() (*eos.Packet, error) {
	packet, err := eos.ReadPacket(p.reader)
	if err != nil {
		return nil, fmt.Errorf("connection: read: %s", err)
	}
	return packet, nil
}

func (p *Peer) Init(errChan chan error) (ready chan bool) {

	ready = make(chan bool, 1)
	if p.listener {

		go func() {
			fmt.Println("Listening on:", p.Address)

			ln, err := net.Listen("tcp", p.Address)
			if err != nil {
				errChan <- fmt.Errorf("peer init: listening %s: %s", p.Address, err)
			}

			fmt.Println("Accepting connection on:\n", p.Address)
			conn, err := ln.Accept()
			if err != nil {
				errChan <- fmt.Errorf("peer init: accepting connection on %s: %s", p.Address, err)
			}
			fmt.Println("Connected on:", p.Address)

			p.connection = conn
			p.reader = bufio.NewReader(p.connection)
			ready <- true
		}()

	} else {
		fmt.Println("Dialing:", p.Address)
		conn, err := net.Dial("tcp", p.Address)
		if err != nil {
			errChan <- fmt.Errorf("peer init: dial %s: %s", p.Address, err)
		}
		p.connection = conn
		p.reader = bufio.NewReader(conn)
		ready <- true
	}

	return
}

func (p *Peer) Write(bytes []byte) (int, error) {

	return p.connection.Write(bytes)
}

func (p *Peer) WriteP2PMessage(message eos.P2PMessage) (err error) {

	packet := &eos.Packet{
		Type:       message.GetType(),
		P2PMessage: message,
	}

	encoder := eos.NewEncoder(p.connection)
	err = encoder.Encode(packet)

	return
}

func (p *Peer) SendSyncRequest(startBlockNum uint32, endBlockNumber uint32) (err error) {
	println("SendSyncRequest start [%d] end [%d]\n", startBlockNum, endBlockNumber)
	syncRequest := &eos.SyncRequestMessage{
		StartBlock: startBlockNum,
		EndBlock:   endBlockNumber,
	}

	return p.WriteP2PMessage(syncRequest)
}

func (p *Peer) SendHandshake(info *HandshakeInfo) (err error) {

	publicKey, err := ecc.NewPublicKey("EOS1111111111111111111111111111111114T1Anm")
	if err != nil {
		fmt.Println("publicKey : ", err)
		err = fmt.Errorf("sending handshake to %s: create public key: %s", p.Address, err)
		return
	}

	tstamp := eos.Tstamp{Time: info.HeadBlockTime}

	signature := ecc.Signature{
		Curve:   ecc.CurveK1,
		Content: make([]byte, 65, 65),
	}

	handshake := &eos.HandshakeMessage{
		NetworkVersion:           1206,
		ChainID:                  p.chainID,
		NodeID:                   make([]byte, 32),
		Key:                      publicKey,
		Time:                     tstamp,
		Token:                    make([]byte, 32, 32), // token[:]
		Signature:                signature,
		P2PAddress:               p.Address,
		LastIrreversibleBlockNum: info.LastIrreversibleBlockNum,
		LastIrreversibleBlockID:  info.LastIrreversibleBlockID,
		HeadNum:                  info.HeadBlockNum,
		HeadID:                   info.HeadBlockID,
		OS:                       runtime.GOOS,
		Agent:                    p.agent,
		Generation:               int16(1),
	}

	err = p.WriteP2PMessage(handshake)
	if err != nil {
		err = fmt.Errorf("sending handshake to %s: %s", p.Address, err)
	}
	return
}

type Catchup struct {
	IsCatchingUp        bool
	requestedStartBlock uint32
	requestedEndBlock   uint32
	headBlock           uint32
	originHeadBlock     uint32
}

func (c *Catchup) sendSyncRequestTo(peer *Peer) error {

	c.IsCatchingUp = true

	delta := c.originHeadBlock - c.headBlock

	c.requestedStartBlock = c.headBlock + 1
	c.requestedEndBlock = c.headBlock + uint32(math.Min(float64(delta), 250))

	fmt.Printf("Sending sync request to origin: start block [%d] end block [%d]\n", c.requestedStartBlock, c.requestedEndBlock)
	err := peer.SendSyncRequest(c.requestedStartBlock, c.requestedEndBlock+1)

	if err != nil {
		return fmt.Errorf("send sync request: %s", err)
	}

	return nil

}
