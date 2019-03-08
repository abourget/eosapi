package eos

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/eoscanada/eos-go/ecc"
)

type API struct {
	HttpClient *http.Client
	BaseURL    string
	Signer     Signer
	Debug      bool
	Compress   CompressionType
	// Header is one or more headers to be added to all outgoing calls
	Header                  http.Header
	DefaultMaxCPUUsageMS    uint8
	DefaultMaxNetUsageWords uint32 // in 8-bytes words

	lastGetInfo      *InfoResp
	lastGetInfoStamp time.Time
	lastGetInfoLock  sync.Mutex

	customGetRequiredKeys func(tx *Transaction) ([]ecc.PublicKey, error)
}

func New(baseURL string) *API {
	api := &API{
		HttpClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DisableKeepAlives:     true, // default behavior, because of `nodeos`'s lack of support for Keep alives.
			},
		},
		BaseURL:  baseURL,
		Compress: CompressionZlib,
		Header:   make(http.Header),
	}

	return api
}

// FixKeepAlives tests the remote server for keepalive support (the
// main `nodeos` software doesn't in the version from March 22nd
// 2018).  Some endpoints front their node with a keep-alive
// supporting web server.  Adjust the `KeepAlive` support of the
// client accordingly.
func (api *API) FixKeepAlives() bool {
	// Yeah, to provoke a keep alive, you need to query twice.
	for i := 0; i < 5; i++ {
		_, err := api.GetInfo()
		if api.Debug {
			log.Println("err", err)
		}
		if err == io.EOF {
			if tr, ok := api.HttpClient.Transport.(*http.Transport); ok {
				tr.DisableKeepAlives = true
				return true
			}
		}
		_, err = api.GetNetConnections()
		if api.Debug {
			log.Println("err", err)
		}
		if err == io.EOF {
			if tr, ok := api.HttpClient.Transport.(*http.Transport); ok {
				tr.DisableKeepAlives = true
				return true
			}
		}
	}
	return false
}

func (api *API) EnableKeepAlives() bool {
	if tr, ok := api.HttpClient.Transport.(*http.Transport); ok {
		tr.DisableKeepAlives = false
		return true
	}
	return false
}

func (api *API) SetCustomGetRequiredKeys(f func(tx *Transaction) ([]ecc.PublicKey, error)) {
	api.customGetRequiredKeys = f
}

func (api *API) SetSigner(s Signer) {
	api.Signer = s
}

// ProducerPause will pause block production on a nodeos with
// `producer_api` plugin loaded.
func (api *API) ProducerPause() error {
	return api.call("producer", "pause", nil, nil)
}

// CreateSnapshot will write a snapshot file on a nodeos with
// `producer_api` plugin loaded.
func (api *API) CreateSnapshot() (out *CreateSnapshotResp, err error) {
	err = api.call("producer", "create_snapshot", nil, &out)
	return
}

// GetIntegrityHash will produce a hash corresponding to current
// state. Requires `producer_api` and useful when loading
// from a snapshot
func (api *API) GetIntegrityHash() (out *GetIntegrityHashResp, err error) {
	err = api.call("producer", "get_integrity_hash", nil, &out)
	return
}

// ProducerResume will resume block production on a nodeos with
// `producer_api` plugin loaded. Obviously, this needs to be a
// producing node on the producers schedule for it to do anything.
func (api *API) ProducerResume() error {
	return api.call("producer", "resume", nil, nil)
}

// IsProducerPaused queries the blockchain for the pause statement of
// block production.
func (api *API) IsProducerPaused() (out bool, err error) {
	err = api.call("producer", "paused", nil, &out)
	return
}

func (api *API) GetAccount(name AccountName) (out *AccountResp, err error) {
	err = api.call("chain", "get_account", M{"account_name": name}, &out)
	return
}

func (api *API) GetRawCodeAndABI(account AccountName) (out *GetRawCodeAndABIResp, err error) {
	err = api.call("chain", "get_raw_code_and_abi", M{"account_name": account}, &out)
	return
}

func (api *API) GetCode(account AccountName) (out *GetCodeResp, err error) {
	err = api.call("chain", "get_code", M{"account_name": account, "code_as_wasm": true}, &out)
	return
}

func (api *API) GetCodeHash(account AccountName) (out Checksum256, err error) {
	resp := GetCodeHashResp{}
	if err = api.call("chain", "get_code_hash", M{"account_name": account}, &resp); err != nil {
		return
	}

	buffer, err := hex.DecodeString(resp.CodeHash)
	return Checksum256(buffer), err
}

func (api *API) GetABI(account AccountName) (out *GetABIResp, err error) {
	err = api.call("chain", "get_abi", M{"account_name": account}, &out)
	return
}

func (api *API) ABIJSONToBin(code AccountName, action Name, payload M) (out HexBytes, err error) {
	resp := ABIJSONToBinResp{}
	err = api.call("chain", "abi_json_to_bin", M{"code": code, "action": action, "args": payload}, &resp)
	if err != nil {
		return
	}

	buffer, err := hex.DecodeString(resp.Binargs)
	return HexBytes(buffer), err
}

func (api *API) ABIBinToJSON(code AccountName, action Name, payload HexBytes) (out M, err error) {
	resp := ABIBinToJSONResp{}
	err = api.call("chain", "abi_bin_to_json", M{"code": code, "action": action, "binargs": payload}, &resp)
	if err != nil {
		return
	}

	return resp.Args, nil
}

func (api *API) WalletCreate(walletName string) (err error) {
	return api.call("wallet", "create", walletName, nil)
}

func (api *API) WalletOpen(walletName string) (err error) {
	return api.call("wallet", "open", walletName, nil)
}

func (api *API) WalletLock(walletName string) (err error) {
	return api.call("wallet", "lock", walletName, nil)
}

func (api *API) WalletLockAll() (err error) {
	return api.call("wallet", "lock_all", nil, nil)
}

func (api *API) WalletUnlock(walletName, password string) (err error) {
	return api.call("wallet", "unlock", []string{walletName, password}, nil)
}

// WalletImportKey loads a new WIF-encoded key into the wallet.
func (api *API) WalletImportKey(walletName, wifPrivKey string) (err error) {
	return api.call("wallet", "import_key", []string{walletName, wifPrivKey}, nil)
}

func (api *API) WalletPublicKeys() (out []ecc.PublicKey, err error) {
	var textKeys []string
	err = api.call("wallet", "get_public_keys", nil, &textKeys)
	if err != nil {
		return nil, err
	}

	for _, k := range textKeys {
		newKey, err := ecc.NewPublicKey(k)
		if err != nil {
			return nil, err
		}

		out = append(out, newKey)
	}
	return
}

func (api *API) ListWallets(walletName ...string) (out []string, err error) {
	err = api.call("wallet", "list_wallets", walletName, &out)
	if err != nil {
		return nil, err
	}

	return
}

func (api *API) ListKeys(walletNames ...string) (out []*ecc.PrivateKey, err error) {
	var textKeys []string
	err = api.call("wallet", "list_keys", walletNames, &textKeys)
	if err != nil {
		return nil, err
	}

	for _, k := range textKeys {
		newKey, err := ecc.NewPrivateKey(k)
		if err != nil {
			return nil, err
		}

		out = append(out, newKey)
	}
	return
}

func (api *API) GetPublicKeys() (out []*ecc.PublicKey, err error) {
	var textKeys []string
	err = api.call("wallet", "get_public_keys", nil, &textKeys)
	if err != nil {
		return nil, err
	}

	for _, k := range textKeys {
		newKey, err := ecc.NewPublicKey(k)
		if err != nil {
			return nil, err
		}

		out = append(out, &newKey)
	}
	return
}

func (api *API) WalletSetTimeout(timeout int32) (err error) {
	return api.call("wallet", "set_timeout", timeout, nil)
}

func (api *API) WalletSignTransaction(tx *SignedTransaction, chainID []byte, pubKeys ...ecc.PublicKey) (out *WalletSignTransactionResp, err error) {
	var textKeys []string
	for _, key := range pubKeys {
		textKeys = append(textKeys, key.String())
	}

	err = api.call("wallet", "sign_transaction", []interface{}{
		tx,
		textKeys,
		hex.EncodeToString(chainID),
	}, &out)
	return
}

// SignPushActions will create a transaction, fill it with default
// values, sign it and submit it to the chain.  It is the highest
// level function on top of the `/v1/chain/push_transaction` endpoint.
func (api *API) SignPushActions(a ...*Action) (out *PushTransactionFullResp, err error) {
	return api.SignPushActionsWithOpts(a, nil)
}

func (api *API) SignPushActionsWithOpts(actions []*Action, opts *TxOptions) (out *PushTransactionFullResp, err error) {
	if opts == nil {
		opts = &TxOptions{}
	}

	if err := opts.FillFromChain(api); err != nil {
		return nil, err
	}

	tx := NewTransaction(actions, opts)

	return api.SignPushTransaction(tx, opts.ChainID, opts.Compress)
}

// SignPushTransaction will sign a transaction and submit it to the
// chain.
func (api *API) SignPushTransaction(tx *Transaction, chainID Checksum256, compression CompressionType) (out *PushTransactionFullResp, err error) {
	_, packed, err := api.SignTransaction(tx, chainID, compression)
	if err != nil {
		return nil, err
	}

	return api.PushTransaction(packed)
}

// SignTransaction will sign and pack a transaction, but not submit to
// the chain.  It lives on the `api` object because it might query the
// blockchain to learn which keys are required to sign this particular
// transaction.
//
// You can override the way we request keys (which defaults to
// `api.GetRequiredKeys()`) with SetCustomGetRequiredKeys().
//
// To sign a transaction, you need a Signer defined on the `API`
// object. See SetSigner.
func (api *API) SignTransaction(tx *Transaction, chainID Checksum256, compression CompressionType) (*SignedTransaction, *PackedTransaction, error) {
	if api.Signer == nil {
		return nil, nil, fmt.Errorf("no Signer configured")
	}

	stx := NewSignedTransaction(tx)

	var requiredKeys []ecc.PublicKey
	if api.customGetRequiredKeys != nil {
		var err error
		requiredKeys, err = api.customGetRequiredKeys(tx)
		if err != nil {
			return nil, nil, fmt.Errorf("custom_get_required_keys: %s", err)
		}
	} else {
		resp, err := api.GetRequiredKeys(tx)
		if err != nil {
			return nil, nil, fmt.Errorf("get_required_keys: %s", err)
		}
		requiredKeys = resp.RequiredKeys
	}

	signedTx, err := api.Signer.Sign(stx, chainID, requiredKeys...)
	if err != nil {
		return nil, nil, fmt.Errorf("signing through wallet: %s", err)
	}

	packed, err := signedTx.Pack(compression)
	if err != nil {
		return nil, nil, err
	}

	return signedTx, packed, nil
}

// PushTransaction submits a properly filled (tapos), packed and
// signed transaction to the blockchain.
func (api *API) PushTransaction(tx *PackedTransaction) (out *PushTransactionFullResp, err error) {
	err = api.call("chain", "push_transaction", tx, &out)
	return
}

func (api *API) PushTransactionRaw(tx *PackedTransaction) (out json.RawMessage, err error) {
	err = api.call("chain", "push_transaction", tx, &out)
	return
}

func (api *API) GetInfo() (out *InfoResp, err error) {
	err = api.call("chain", "get_info", nil, &out)
	return
}

func (api *API) cachedGetInfo() (*InfoResp, error) {
	api.lastGetInfoLock.Lock()
	defer api.lastGetInfoLock.Unlock()

	var info *InfoResp
	var err error

	if !api.lastGetInfoStamp.IsZero() && time.Now().Add(-1*time.Second).Before(api.lastGetInfoStamp) {
		info = api.lastGetInfo
	} else {
		info, err = api.GetInfo()
		if err != nil {
			return nil, err
		}
		api.lastGetInfoStamp = time.Now()
		api.lastGetInfo = info
	}
	if err != nil {
		return nil, err
	}

	return api.lastGetInfo, nil
}

func (api *API) GetNetConnections() (out []*NetConnectionsResp, err error) {
	err = api.call("net", "connections", nil, &out)
	return
}

func (api *API) NetConnect(host string) (out NetConnectResp, err error) {
	err = api.call("net", "connect", host, &out)
	return
}

func (api *API) NetDisconnect(host string) (out NetDisconnectResp, err error) {
	err = api.call("net", "disconnect", host, &out)
	return
}

func (api *API) GetNetStatus(host string) (out *NetStatusResp, err error) {
	err = api.call("net", "status", M{"host": host}, &out)
	return
}

func (api *API) GetBlockByID(id string) (out *BlockResp, err error) {
	err = api.call("chain", "get_block", M{"block_num_or_id": id}, &out)
	return
}

// GetScheduledTransactionsWithBounds returns scheduled transactions within specified bounds
func (api *API) GetScheduledTransactionsWithBounds(lower_bound string, limit uint32) (out *ScheduledTransactionsResp, err error) {
	err = api.call("chain", "get_scheduled_transactions", M{"json": true, "lower_bound": lower_bound, "limit": limit}, &out)
	return
}

// GetScheduledTransactions returns the Top 100 scheduled transactions
func (api *API) GetScheduledTransactions() (out *ScheduledTransactionsResp, err error) {
	return api.GetScheduledTransactionsWithBounds("", 100)
}

func (api *API) GetProducers() (out *ProducersResp, err error) {
	/*
		+FC_REFLECT( eosio::chain_apis::read_only::get_producers_params, (json)(lower_bound)(limit) )
		+FC_REFLECT( eosio::chain_apis::read_only::get_producers_result, (rows)(total_producer_vote_weight)(more) ); */
	err = api.call("chain", "get_producers", M{"json": true}, &out)
	return
}

func (api *API) GetBlockByNum(num uint32) (out *BlockResp, err error) {
	err = api.call("chain", "get_block", M{"block_num_or_id": fmt.Sprintf("%d", num)}, &out)
	//err = api.call("chain", "get_block", M{"block_num_or_id": num}, &out)
	return
}

func (api *API) GetBlockByNumOrID(query string) (out *SignedBlock, err error) {
	err = api.call("chain", "get_block", M{"block_num_or_id": query}, &out)
	return
}

func (api *API) GetBlockByNumOrIDRaw(query string) (out interface{}, err error) {
	err = api.call("chain", "get_block", M{"block_num_or_id": query}, &out)
	return
}

func (api *API) GetDBSize() (out *DBSizeResp, err error) {
	err = api.call("db_size", "get", nil, &out)
	return
}

func (api *API) GetTransaction(id string) (out *TransactionResp, err error) {
	err = api.call("history", "get_transaction", M{"id": id}, &out)
	return
}

func (api *API) GetTransactionRaw(id string) (out json.RawMessage, err error) {
	err = api.call("history", "get_transaction", M{"id": id}, &out)
	return
}

func (api *API) GetActions(params GetActionsRequest) (out *ActionsResp, err error) {
	err = api.call("history", "get_actions", params, &out)
	return
}

func (api *API) GetTransactions(name AccountName) (out *TransactionsResp, err error) {
	err = api.call("account_history", "get_transactions", M{"account_name": name}, &out)
	return
}

func (api *API) GetTableByScope(params GetTableByScopeRequest) (out *GetTableByScopeResp, err error) {
	err = api.call("chain", "get_table_by_scope", params, &out)
	return
}

func (api *API) GetTableRows(params GetTableRowsRequest) (out *GetTableRowsResp, err error) {
	err = api.call("chain", "get_table_rows", params, &out)
	return
}

func (api *API) GetRawABI(params GetRawABIRequest) (out *GetRawABIResp, err error) {
	err = api.call("chain", "get_raw_abi", params, &out)
	return
}

func (api *API) GetRequiredKeys(tx *Transaction) (out *GetRequiredKeysResp, err error) {
	keys, err := api.Signer.AvailableKeys()
	if err != nil {
		return nil, err
	}

	err = api.call("chain", "get_required_keys", M{"transaction": tx, "available_keys": keys}, &out)
	return
}

func (api *API) GetCurrencyBalance(account AccountName, symbol string, code AccountName) (out []Asset, err error) {
	params := M{"account": account, "code": code}
	if symbol != "" {
		params["symbol"] = symbol
	}
	err = api.call("chain", "get_currency_balance", params, &out)
	return
}

func (api *API) GetCurrencyStats(code AccountName, symbol string) (out *GetCurrencyStatsResp, err error) {
	params := M{"code": code, "symbol": symbol}

	outWrapper := make(map[string]*GetCurrencyStatsResp)
	err = api.call("chain", "get_currency_stats", params, &outWrapper)
	out = outWrapper[symbol]

	return
}

// See more here: libraries/chain/contracts/abi_serializer.cpp:58...

func (api *API) call(baseAPI string, endpoint string, body interface{}, out interface{}) error {
	jsonBody, err := enc(body)
	if err != nil {
		return err
	}

	targetURL := fmt.Sprintf("%s/v1/%s/%s", api.BaseURL, baseAPI, endpoint)
	req, err := http.NewRequest("POST", targetURL, jsonBody)
	if err != nil {
		return fmt.Errorf("NewRequest: %s", err)
	}

	for k, v := range api.Header {
		if req.Header == nil {
			req.Header = http.Header{}
		}
		req.Header[k] = append(req.Header[k], v...)
	}

	if api.Debug {
		// Useful when debugging API calls
		requestDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("-------------------------------")
		fmt.Println(string(requestDump))
		fmt.Println("")
	}

	resp, err := api.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %s", req.URL.String(), err)
	}
	defer resp.Body.Close()

	var cnt bytes.Buffer
	_, err = io.Copy(&cnt, resp.Body)
	if err != nil {
		return fmt.Errorf("Copy: %s", err)
	}

	if resp.StatusCode == 404 {
		var apiErr APIError
		if err := json.Unmarshal(cnt.Bytes(), &apiErr); err != nil {
			return ErrNotFound
		}
		return apiErr
	}

	if resp.StatusCode > 299 {
		var apiErr APIError
		if err := json.Unmarshal(cnt.Bytes(), &apiErr); err != nil {
			return fmt.Errorf("%s: status code=%d, body=%s", req.URL.String(), resp.StatusCode, cnt.String())
		}

		// Handle cases where some API calls (/v1/chain/get_account for example) returns a 500
		// error when retrieving data that does not exist.
		if apiErr.IsUnknownKeyError() {
			return ErrNotFound
		}

		return apiErr
	}

	if api.Debug {
		fmt.Println("RESPONSE:")
		responseDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("-------------------------------")
		fmt.Println(cnt.String())
		fmt.Println("-------------------------------")
		fmt.Printf("%q\n", responseDump)
		fmt.Println("")
	}

	if err := json.Unmarshal(cnt.Bytes(), &out); err != nil {
		return fmt.Errorf("Unmarshal: %s", err)
	}

	return nil
}

var ErrNotFound = errors.New("resource not found")

type M map[string]interface{}

func enc(v interface{}) (io.Reader, error) {
	if v == nil {
		return nil, nil
	}

	cnt, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	//fmt.Println("BODY", string(cnt))

	return bytes.NewReader(cnt), nil
}
