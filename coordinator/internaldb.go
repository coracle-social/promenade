package main

import (
	"encoding/hex"
	"fmt"

	"fiatjaf.com/leafdb"
	"github.com/nbd-wtf/go-nostr"
	"google.golang.org/protobuf/proto"
)

const (
	TypeNothing leafdb.DataType = 0
	TypeGroup   leafdb.DataType = 1
	TypePubKey  leafdb.DataType = 2
)

func NewInternalDB(path string) (*InternalDB, error) {
	ldb, err := leafdb.New(path, leafdb.Options[any]{
		Encode: func(t leafdb.DataType, value any) ([]byte, error) {
			switch t {
			case TypeNothing:
				return []byte{0}, nil
			case TypePubKey:
				return hex.DecodeString(value.(string))
			default:
				return proto.Marshal(value.(proto.Message))
			}
		},
		Decode: func(t leafdb.DataType, buf []byte) (any, error) {
			switch t {
			case TypeNothing:
				return nil, nil
			case TypeGroup:
				v := &Group{}
				err := proto.Unmarshal(buf, v)
				return v, err
			case TypePubKey:
				return hex.EncodeToString(buf), nil
			default:
				return nil, fmt.Errorf("what is this? %v", t)
			}
		},
		Indexes: map[string]leafdb.IndexDefinition[any]{
			"group-by-pubkey": {
				Version: 1,
				Types:   []leafdb.DataType{TypeGroup},
				Emit: func(t leafdb.DataType, data any, emit func([]byte)) {
					g := data.(*Group)
					ipk := make([]byte, 16)
					hex.Decode(ipk, []byte(g.Pubkey[0:32]))
					emit(ipk)
				},
			},
			"group-by-handler-pubkey": {
				Version: 1,
				Types:   []leafdb.DataType{TypeGroup},
				Emit: func(t leafdb.DataType, data any, emit func([]byte)) {
					g := data.(*Group)
					pk, _ := nostr.GetPublicKey(g.Handler)
					ipk := make([]byte, 16)
					hex.Decode(ipk, []byte(pk[0:32]))
					emit(ipk)
				},
			},
		},
		Views: map[string]leafdb.ViewDefinition[any]{
			"signers": {
				Version: 1,
				Types:   []leafdb.DataType{TypeGroup},
				Emit: func(t leafdb.DataType, value any, emit func(idxkey []byte, t leafdb.DataType, value any)) {
					g := value.(*Group)
					for _, signer := range g.Signers {
						ipk := make([]byte, 16)
						hex.Decode(ipk, []byte(signer.Pubkey[0:32]))
						emit(ipk, TypePubKey, g.Pubkey)
					}
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return &InternalDB{ldb}, err
}

type InternalDB struct {
	*leafdb.DB[any]
}

func (internal InternalDB) saveGroup(g *Group) error {
	_, err := internal.DB.Create(TypeGroup, g)
	return err
}

func (internal InternalDB) getGroupByHandlerPubkey(pubkey string) (*Group, error) {
	ipk := make([]byte, 16)
	hex.Decode(ipk, []byte(pubkey[0:32]))
	for res := range internal.DB.Query(leafdb.ExactQuery("group-by-handler-pubkey", ipk)) {
		return res.(*Group), nil
	}
	return nil, fmt.Errorf("no group found for pubkey %s", pubkey)
}

func (internal InternalDB) checkSignerExistence(pubkey string) bool {
	ipk := make([]byte, 16)
	hex.Decode(ipk, []byte(pubkey[0:32]))
	for range internal.DB.View(leafdb.ExactQuery("signers", ipk)) {
		return true
	}
	return false
}

func (internal InternalDB) getSignerUsers(pubkey string) []string {
	ipk := make([]byte, 16)
	hex.Decode(ipk, []byte(pubkey[0:32]))

	users := make([]string, 0, 12)
	for user := range internal.DB.View(leafdb.ExactQuery("signers", ipk)) {
		users = append(users, user.(string))
	}

	return users
}
