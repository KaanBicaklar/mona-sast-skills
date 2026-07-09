---
name: smart-contract-security
description: >-
  SAST detection methodology for Solidity/EVM smart-contract flaws (CWE-841 /
  SWC Registry) — reentrancy, integer overflow/underflow, broken access control
  and tx.origin auth, unchecked low-level calls, delegatecall to untrusted code,
  uninitialized storage pointers, front-running/MEV, block-value dependence,
  weak randomness, unprotected selfdestruct, signature replay, and price-oracle/
  flash-loan manipulation. Use when reviewing .sol contracts. Writes confirmed
  findings to findings/47-smart-contract-security.md.
---

# Smart Contract Security (EVM) — SAST Methodology

**Class:** Smart Contract (EVM) · **CWE-841 / SWC Registry** · **OWASP:** Web3 / smart-contract
**Findings file:** `findings/47-smart-contract-security.md`

## 1. Overview

Smart-contract flaws let anyone who can send a transaction drain assets, seize
control, or manipulate state, because the contract's logic mishandles external
calls, arithmetic, authorization, or on-chain data an attacker can influence. The
core test: can an external caller reach a state-changing path that (a) makes an
external call before updating state, (b) trusts a spoofable/manipulable value
(`tx.origin`, `block.timestamp`, an oracle price), or (c) lacks an authorization
check? Contracts execute **on-chain**, so findings are not Burp-reproducible —
reproduce with a testnet transaction or a Foundry PoC (see §11).

## 2. Where it lives

- `.sol` source: functions that send ETH/tokens (`.call{value:}`, `.transfer`,
  `.send`, ERC-20/721 transfers), any external/low-level call, `delegatecall`,
  `selfdestruct`, and privileged setters/withdrawals.
- Access-control code: `onlyOwner`/role modifiers, `require(msg.sender == …)`,
  `tx.origin` comparisons, initializer functions in upgradeable (proxy) contracts.
- Arithmetic in pre-0.8 contracts (no built-in overflow checks) or inside
  `unchecked { … }` blocks in 0.8+.
- Anything reading `block.timestamp`, `block.number`, `blockhash`, `block.difficulty`
  /`prevrandao`, or an external price feed.
- Signature-verification code (`ecrecover`, permit/meta-tx) and nonce handling.
- Proxy/upgradeable patterns (`delegatecall`, uninitialized implementation).

## 3. Sources (tainted input)

Anything an attacker controls or influences on-chain: **transaction parameters**
(`msg.data`, function args), `msg.sender`/`msg.value`, the **order and timing of
transactions** (mempool front-running / MEV, flash-loan-funded calls within one
tx), **externally-callable callbacks** (ERC-777 `tokensReceived`, ERC-721
`onERC721Received`, fallback/`receive`) that re-enter, **manipulable market prices**
from a spot AMM used as an oracle, and miner/validator-influenced block values.
Second-order: uninitialized storage that an attacker-controlled write aliases.

## 4. Sinks (dangerous operations)

```solidity
// Reentrancy (SWC-107) — external call BEFORE state update
function withdraw() external {
    uint bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}("");   // hands control to attacker
    require(ok);
    balances[msg.sender] = 0;                         // state updated too late → re-enter
}

// Access control — spoofable auth (SWC-115) / missing modifier
function setOwner(address n) external {               // NO onlyOwner → anyone calls
    owner = n;
}
require(tx.origin == owner);                          // tx.origin auth → phishing-relay bypass

// Unchecked low-level call return (SWC-104)
addr.call(data);                                      // return value ignored → silent failure
payable(to).send(amount);                             // send() returns bool, not checked

// delegatecall to untrusted (SWC-112) — attacker code runs in THIS storage context
(bool s,) = target.delegatecall(msg.data);            // target attacker-controlled

// Integer overflow/underflow (pre-0.8 or unchecked)
unchecked { balances[msg.sender] -= amt; }            // underflow → huge balance

// Block-value dependence / weak randomness (SWC-116/120)
uint winner = uint(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number-1)))) % n;
if (block.timestamp > deadline) { … }                 // miner-tunable within ~15s

// Unprotected selfdestruct
function kill() external { selfdestruct(payable(msg.sender)); }   // anyone bricks/drains

// Signature replay — no nonce / no domain separator
require(ecrecover(hash, v, r, s) == signer);          // same sig replays across tx/chains

// Uninitialized storage pointer (older Solidity)
Struct storage s;                                     // points to slot 0 → corrupts state
s.x = 1;

// Price-oracle manipulation / flash loan
uint price = uniPair.getReserves();                   // spot reserves as price → flash-loan skew
```

Dangerous patterns marked above: external call before state write, missing
modifier, `tx.origin` auth, ignored `call`/`send` return, `delegatecall` to
untrusted target, `unchecked`/pre-0.8 arithmetic on balances, `block.*` used for
logic/randomness, unprotected `selfdestruct`, `ecrecover` without nonce/domain, an
uninitialized `storage` pointer, and spot-AMM price as an oracle.

## 5. Sanitizers / safe patterns

**Safe:** **checks-effects-interactions** ordering (update state *before* the
external call) and/or a `nonReentrant` reentrancy guard (OpenZeppelin
`ReentrancyGuard`), applied to *cross-function* and *read-only* reentrancy too.
Access control via audited `Ownable`/`AccessControl` modifiers and
`msg.sender` (never `tx.origin`). Solidity **0.8+** built-in overflow checks (or
OpenZeppelin `SafeMath` pre-0.8); keep `unchecked` blocks provably safe. Check the
return value of every low-level `call`/`send`, or use `call{value:}` with a
`require(ok)`; prefer pull-over-push payments. Never `delegatecall` to an
address an attacker can set; lock proxy implementations with an initializer guard
(`initializer`/`_disableInitializers`). Use a manipulation-resistant oracle
(**Chainlink**, or a **TWAP**) instead of spot reserves. EIP-712 typed signatures
with a per-account **nonce** and a **domain separator** (chainId, contract address)
to stop replay. Restrict `selfdestruct`/upgrade/withdraw to `onlyOwner`/roles.
Verify with **Slither** (static), **Mythril**/**Manticore** (symbolic), and
**Foundry**/**Echidna** (fuzz/invariant tests).

**Fails / not a real sanitizer:**
- A reentrancy guard on only *one* function while a sibling reads/writes the same
  state (cross-function / read-only reentrancy still drains).
- `tx.origin == owner` — a malicious contract the owner calls relays the auth.
- `require(success)` missing after `.call`, so a failed transfer looks successful.
- Using `block.timestamp`/`blockhash`/`prevrandau` for "randomness" — validators
  influence or know these; only a VRF (e.g. Chainlink VRF) or commit-reveal is sound.
- A single-block spot price "sanity check" against the same manipulable AMM.
- `unchecked` used "for gas" around subtraction on a user-controlled balance.
- An upgradeable contract left with an **unprotected `initialize()`** — anyone
  becomes owner (proxy takeover).

## 6. Detection methodology

1. **Grep the `.sol` files for the dangerous sinks:**
   ```
   rg -n 'call\{value:|\.call\.value\(|\.call\(|delegatecall|\.send\(|\.transfer\(' 
   rg -n 'tx\.origin' 
   rg -n 'selfdestruct|suicide' 
   rg -n 'block\.(timestamp|number|difficulty|prevrandao)|blockhash' 
   rg -n 'unchecked\s*\{|using SafeMath|pragma solidity \^?0\.[0-7]' 
   rg -n 'ecrecover|initialize\(|initializer' 
   ```
2. **Reentrancy:** for each external call that sends value or calls untrusted code,
   check whether **state is updated after** the call and whether a guard is present
   (and whether siblings sharing that state are also guarded).
3. **Access control:** for every state-changing/privileged function, confirm a
   correct modifier and `msg.sender` check; flag `tx.origin` and any missing
   `onlyOwner`/role. In proxies, confirm the initializer is one-time and protected.
4. **Arithmetic:** on pre-0.8 pragmas or inside `unchecked`, verify no
   attacker-controlled over/underflow (especially balance subtraction).
5. **External-call return & delegatecall target:** is every low-level return
   checked? Is any `delegatecall` target attacker-settable?
6. **On-chain data trust:** is any `block.*`/`blockhash` or spot price used for
   randomness, pricing, or control flow? Is `ecrecover` protected by a nonce +
   domain separator?
7. **Confirm with tooling:** run **Slither** and **Mythril**; write a **Foundry**
   PoC/invariant to prove exploitability; model **flash-loan** funding for oracle/
   economic attacks.

## 7. Modern & niche variants

- **Read-only reentrancy:** a `view` function (e.g. an LP price getter) returns
  stale mid-transaction state during a reentrant callback, corrupting an *external*
  protocol that trusts it.
- **Cross-function / cross-contract reentrancy:** re-entering a *different* function
  (or a paired contract) that shares the same unguarded state.
- **ERC-777/ERC-721 hook reentrancy:** `tokensReceived`/`onERC721Received` give the
  attacker a callback even on "safe" transfers.
- **Flash-loan price-oracle manipulation:** borrow → skew a spot AMM → exploit a
  contract that reads that price → repay, all in one atomic tx (consumes an
  `OUTBOUND_REQUEST`-style external oracle/flash-loan dependency).
- **Sandwich / front-running (MEV):** a searcher orders txs around the victim's to
  extract value (slippage, liquidation, NFT mint).
- **Signature replay across chains / missing nonce:** same `ecrecover` signature
  reused on another chainId or a second time without a nonce.
- **Uninitialized proxy / storage-collision:** unprotected `initialize()` or a
  storage layout mismatch between proxy and implementation → takeover.
- **Unprotected `selfdestruct` in a library used via `delegatecall`** (the Parity
  multisig class) — bricks all dependents.
- **Gas-griefing / DoS via unbounded loop** over a user-growable array, or a
  `require` that can be forced to revert (push-payment to a reverting receiver).

## 8. Common false positives

- External call *after* all state updates with a `nonReentrant` guard (correct CEI).
- `unchecked` blocks on values provably bounded (loop counters, constants).
- `block.timestamp` used only for a coarse, non-security-critical deadline where a
  ~15s validator skew is immaterial and no value depends on precision.
- `tx.origin` used solely to detect/refuse contract callers (`require(tx.origin ==
  msg.sender)`) rather than for authorization.
- Low-level `call` whose return **is** checked, or `transfer`/`safeTransfer` wrappers
  that revert on failure.
- 0.8+ arithmetic with no `unchecked` (overflow reverts by default).

## 9. Severity & exploitability

Base **High**. **Critical** when an external caller can drain funds or seize
ownership/upgrade rights (reentrancy withdrawal, missing-`onlyOwner` setter,
unprotected `initialize`/`selfdestruct`, delegatecall takeover, flash-loan oracle
drain) — `DATA_WRITE`(asset drain)/`AUTHZ_BYPASS`. **Medium** for
griefing/DoS, or block-value dependence with bounded impact. Weight by TVL at risk
and whether exploitation is atomic/permissionless. Score with
`references/severity-model.md`.

## 10. Remediation

Apply checks-effects-interactions and a `nonReentrant` guard across all functions
sharing state (including `view` getters others rely on). Gate every privileged
function with a correct role/`onlyOwner` modifier using `msg.sender`; protect proxy
initializers. Use Solidity 0.8+ and keep `unchecked` provably safe. Check every
low-level call return; prefer pull payments and `safeTransfer`. Never `delegatecall`
to attacker-settable targets. Use Chainlink/TWAP oracles and VRF/commit-reveal
randomness — never `block.*` or spot price. Add EIP-712 nonces + domain separators
against replay. Restrict/remove `selfdestruct`. Bound loops. Ship only after
Slither/Mythril clean and Foundry/Echidna invariant tests plus an external audit.

## 11. Output

Append each confirmed finding to **`findings/47-smart-contract-security.md`** using
`references/finding-template.md`. Set `Class: Smart Contract (EVM)` and the
specific `CWE`/`SWC` (e.g. CWE-841 with SWC-107 reentrancy, SWC-115 tx.origin,
SWC-104 unchecked call, SWC-112 delegatecall, SWC-116/120 block-value/randomness).

**Reachable over:** `N/A (client/on-chain)` — contracts are not driven by an HTTP
request, so a Burp request is N/A. Reproduce **on-chain**: write a **Foundry**
(`forge test`) PoC or a Hardhat script that deploys the contract on a local
fork/testnet and executes the attack transaction (attacker contract re-entering,
flash-loan-funded oracle skew, unauthorized setter call), asserting the state/asset
change; corroborate with **Slither**/**Mythril** static/symbolic output. Record the
testnet/fork tx hash as the proof. **Exception:** if the actual finding is an
off-chain **backend HTTP API** (e.g. a relayer/indexer/dApp server), set `Reachable
over: Web` and include one Burp-pasteable request to that endpoint.

**Primitives (controlled):** provides `DATA_WRITE`(asset drain / arbitrary state
write), `AUTHZ_BYPASS`(missing modifier / tx.origin / proxy takeover),
`SECRET_LEAK`(private/on-chain data or leaked keys); consumes `OUTBOUND_REQUEST`
(external price oracle / flash-loan liquidity) — sometimes, for oracle-manipulation
and flash-loan chains.

## References
- CWE-841; SWC Registry (SWC-104, SWC-107, SWC-112, SWC-115, SWC-116, SWC-120);
  OWASP Smart Contract Top 10; ConsenSys Smart Contract Best Practices; tooling:
  Slither, Mythril, Manticore, Foundry, Echidna.
