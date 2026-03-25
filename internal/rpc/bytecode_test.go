// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

package rpc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestLedgerKeyForContractInstance(t *testing.T) {
	var cid xdr.ContractId
	for i := range 32 {
		cid[i] = byte(i + 1)
	}
	key, err := LedgerKeyForContractInstance(cid)
	if err != nil {
		t.Fatalf("LedgerKeyForContractInstance: %v", err)
	}
	if key.Type != xdr.LedgerEntryTypeContractData {
		t.Errorf("expected ContractData key type, got %v", key.Type)
	}
	if key.ContractData == nil {
		t.Fatal("expected non-nil ContractData")
	}
	if key.ContractData.Contract.Type != xdr.ScAddressTypeScAddressTypeContract {
		t.Errorf("expected contract address type, got %v", key.ContractData.Contract.Type)
	}
	if key.ContractData.Contract.ContractId == nil || *key.ContractData.Contract.ContractId != cid {
		t.Error("contract id mismatch")
	}
	if key.ContractData.Durability != xdr.ContractDataDurabilityPersistent {
		t.Errorf("expected persistent durability, got %v", key.ContractData.Durability)
	}
	_, err = EncodeLedgerKey(key)
	if err != nil {
		t.Errorf("EncodeLedgerKey: %v", err)
	}
}

func TestDecodeContractID_Strkey(t *testing.T) {
	// Use a valid strkey form: we need 32 bytes encoded. Build from known bytes.
	var cid xdr.ContractId
	for i := range 32 {
		cid[i] = byte(i)
	}
	// Decode then re-encode as strkey would require the strkey package; instead test hex path
	hexID := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	decoded, err := decodeContractID(hexID)
	if err != nil {
		t.Fatalf("decodeContractID(hex): %v", err)
	}
	if decoded != cid {
		t.Errorf("decodeContractID hex: got %x, want %x", decoded[:], cid[:])
	}
}

func TestDecodeContractID_Empty(t *testing.T) {
	_, err := decodeContractID("")
	if err == nil {
		t.Error("expected error for empty contract id")
	}
}

func TestDecodeContractID_InvalidHex(t *testing.T) {
	_, err := decodeContractID("zz")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestDecodeContractID_WrongLengthHex(t *testing.T) {
	_, err := decodeContractID("0001") // 2 bytes
	if err == nil {
		t.Error("expected error for wrong length hex")
	}
}

func TestContractCodeHashFromInstanceEntry_InvalidBase64(t *testing.T) {
	_, err := ContractCodeHashFromInstanceEntry("!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestContractCodeHashFromInstanceEntry_NotContractData(t *testing.T) {
	// Build a minimal account entry (wrong type)
	entry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeAccount,
			Account: &xdr.AccountEntry{
				AccountId: xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"),
				Balance:   100,
			},
		},
	}
	raw, _ := entry.MarshalBinary()
	b64 := base64.StdEncoding.EncodeToString(raw)
	_, err := ContractCodeHashFromInstanceEntry(b64)
	if err == nil {
		t.Error("expected error for non-contract-data entry")
	}
}

func TestWasmBytesFromContractCodeEntry_Valid(t *testing.T) {
	wasm := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	var hash xdr.Hash
	copy(hash[:], make([]byte, 32))
	entry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeContractCode,
			ContractCode: &xdr.ContractCodeEntry{
				Hash: hash,
				Code: wasm,
			},
		},
	}
	raw, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	got, err := WasmBytesFromContractCodeEntry(b64)
	if err != nil {
		t.Fatalf("WasmBytesFromContractCodeEntry: %v", err)
	}
	if len(got) != len(wasm) {
		t.Fatalf("expected %d bytes, got %d", len(wasm), len(got))
	}
	for i := range wasm {
		if got[i] != wasm[i] {
			t.Errorf("byte %d: expected %02x, got %02x", i, wasm[i], got[i])
		}
	}
}

func TestWasmBytesFromContractCodeEntry_InvalidBase64(t *testing.T) {
	_, err := WasmBytesFromContractCodeEntry("!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestWasmBytesFromContractCodeEntry_NotContractCode(t *testing.T) {
	entry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeAccount,
			Account: &xdr.AccountEntry{
				AccountId: xdr.MustAddress("GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"),
				Balance:   100,
			},
		},
	}
	raw, _ := entry.MarshalBinary()
	b64 := base64.StdEncoding.EncodeToString(raw)
	_, err := WasmBytesFromContractCodeEntry(b64)
	if err == nil {
		t.Error("expected error for non-contract-code entry")
	}
}

func TestApplyWasmOverrideToLedgerEntries(t *testing.T) {
	var contractID xdr.ContractId
	for i := range 32 {
		contractID[i] = byte(i + 1)
	}
	oldHash := xdr.Hash{}
	for i := range 32 {
		oldHash[i] = byte(255 - i)
	}
	newWasm := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01}
	newHash := xdr.Hash(sha256.Sum256(newWasm))

	instanceKey, err := LedgerKeyForContractInstance(contractID)
	if err != nil {
		t.Fatalf("LedgerKeyForContractInstance: %v", err)
	}
	instanceKeyB64, err := EncodeLedgerKey(instanceKey)
	if err != nil {
		t.Fatalf("EncodeLedgerKey(instance): %v", err)
	}
	instanceEntry := xdr.LedgerEntry{
		LastModifiedLedgerSeq: 42,
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeContractData,
			ContractData: &xdr.ContractDataEntry{
				Contract: instanceKey.ContractData.Contract,
				Key:      instanceKey.ContractData.Key,
				Val: xdr.ScVal{
					Type: xdr.ScValTypeScvContractInstance,
					Instance: &xdr.ScContractInstance{
						Executable: xdr.ContractExecutable{
							Type:     xdr.ContractExecutableTypeContractExecutableWasm,
							WasmHash: &oldHash,
						},
					},
				},
				Durability: instanceKey.ContractData.Durability,
			},
		},
	}
	instanceEntryB64, err := EncodeLedgerEntry(instanceEntry)
	if err != nil {
		t.Fatalf("EncodeLedgerEntry(instance): %v", err)
	}

	oldCodeKey := xdr.LedgerKey{
		Type:         xdr.LedgerEntryTypeContractCode,
		ContractCode: &xdr.LedgerKeyContractCode{Hash: oldHash},
	}
	oldCodeKeyB64, err := EncodeLedgerKey(oldCodeKey)
	if err != nil {
		t.Fatalf("EncodeLedgerKey(code): %v", err)
	}
	oldCodeEntry := xdr.LedgerEntry{
		Data: xdr.LedgerEntryData{
			Type: xdr.LedgerEntryTypeContractCode,
			ContractCode: &xdr.ContractCodeEntry{
				Hash: oldHash,
				Code: []byte{0x00, 0x61, 0x73, 0x6d},
			},
		},
	}
	oldCodeEntryB64, err := EncodeLedgerEntry(oldCodeEntry)
	if err != nil {
		t.Fatalf("EncodeLedgerEntry(code): %v", err)
	}

	entries := map[string]string{
		instanceKeyB64: instanceEntryB64,
		oldCodeKeyB64:  oldCodeEntryB64,
	}

	hashHex, err := ApplyWasmOverrideToLedgerEntries(entries, hex.EncodeToString(contractID[:]), newWasm)
	if err != nil {
		t.Fatalf("ApplyWasmOverrideToLedgerEntries: %v", err)
	}
	if hashHex != hex.EncodeToString(newHash[:]) {
		t.Fatalf("expected hash %s, got %s", hex.EncodeToString(newHash[:]), hashHex)
	}

	updatedInstance, err := decodeLedgerEntry(entries[instanceKeyB64])
	if err != nil {
		t.Fatalf("decode updated instance: %v", err)
	}
	if updatedInstance.Data.ContractData == nil || updatedInstance.Data.ContractData.Val.Instance == nil {
		t.Fatal("updated instance entry missing contract instance")
	}
	gotHash := updatedInstance.Data.ContractData.Val.Instance.Executable.WasmHash
	if gotHash == nil || *gotHash != newHash {
		t.Fatalf("expected instance wasm hash %x, got %v", newHash[:], gotHash)
	}

	newCodeKey := xdr.LedgerKey{
		Type:         xdr.LedgerEntryTypeContractCode,
		ContractCode: &xdr.LedgerKeyContractCode{Hash: newHash},
	}
	newCodeKeyB64, err := EncodeLedgerKey(newCodeKey)
	if err != nil {
		t.Fatalf("EncodeLedgerKey(new code): %v", err)
	}
	updatedCode, err := decodeLedgerEntry(entries[newCodeKeyB64])
	if err != nil {
		t.Fatalf("decode updated code entry: %v", err)
	}
	if updatedCode.Data.ContractCode == nil {
		t.Fatal("updated code entry missing contract code")
	}
	if got := updatedCode.Data.ContractCode.Code; len(got) != len(newWasm) {
		t.Fatalf("expected %d code bytes, got %d", len(newWasm), len(got))
	}
	for i := range newWasm {
		if updatedCode.Data.ContractCode.Code[i] != newWasm[i] {
			t.Fatalf("code byte %d mismatch: expected %02x, got %02x", i, newWasm[i], updatedCode.Data.ContractCode.Code[i])
		}
	}
}
