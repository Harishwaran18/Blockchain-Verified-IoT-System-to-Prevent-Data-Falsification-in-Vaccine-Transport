# VaccineLedger contract

`VaccineLedger.sol` is the on-chain anchoring target for VChain. The Python
ledger in `vchain/blockchain.py` is the executable reference; this contract
mirrors its commitments on a permissioned EVM network.

## What it stores

- Merkle roots of signed reading digests, with reading count, policy temperature
  bounds, excursion count and timestamp.
- The full digest list per batch, which makes cross-batch replay revert with
  `DuplicateReading`.
- Validator attestations and finalisation at quorum.
- Excursion records (deduplicated by batch + digest + observed temperature).
- Inclusion proofs verified with the same domain separation as Python:
  `sha256(0x00 ‖ digest)` and `sha256(0x01 ‖ left ‖ right)`.

## Functions

| Function | Role |
| --- | --- |
| `anchorBatch(root, digests, minTemp, maxTemp, excursions)` | validator submits a batch and its first attestation |
| `attest(batchIndex)` | another validator attests until quorum finalises the batch |
| `verifyReading(batchIndex, digest, proof, leftFlags)` | view-only Merkle inclusion check |
| `isReadingCommitted(digest)` | cross-batch replay lookup |
| `recordExcursion(batchIndex, digest, observedTemp, reason)` | immutable excursion event |
| `setValidator(address, bool)` | owner manages the validator set |
| `setQuorum(uint256)` | owner changes the quorum |
| `batchAttestations` / `isFinalized` | views |

## Deployment sketch

Using Foundry:

```bash
forge init vchain-contracts
cp contracts/VaccineLedger.sol vchain-contracts/src/
cd vchain-contracts
forge build
forge create src/VaccineLedger.sol:VaccineLedger \
  --rpc-url "$RPC_URL" \
  --private-key "$DEPLOYER_KEY" \
  --constructor-args '[<validator1>,<validator2>,<validator3>]' 2
```

Using Hardhat, deploy with the same constructor arguments. There is no
proxy/upgradeability: the validator set and quorum are mutable by the owner, but
anchored batches are append-only.

## Gateway integration

For each sealed Python block:

1. Convert `block.merkle_root`, `block.digests`, policy temperatures and
   `block.excursion_count` to contract arguments.
2. Submit `anchorBatch` from validator 1.
3. Submit `attest(block.index)` from validators 2 and 3.
4. Wait for `BatchFinalized`, then store the transaction hash alongside the
   local block for reconciliation.

Readings are never sent on-chain; only 32-byte digests and the root. The full
payload stays off-chain and is fetched by digest.

## Proof encoding

Python produces `proof = [{"position": "left"|"right", "hash": hex}]`. Convert
to two arrays:

```python
hashes = [bytes.fromhex(step["hash"]) for step in proof]
left_flags = [step["position"] == "left" for step in proof]
```

The contract computes the same root as `vchain.crypto.merkle_root()`.

## Security notes

- Validators are permissioned addresses. Use multi-sig or HSM-backed signers in
  production; a single compromised validator cannot finalise alone if quorum > 1.
- The owner can change the validator set and quorum, but quorum can never exceed
  the validator count. Use a timelock and a multi-sig, and publish changes.
- `anchorBatch` stores the full digest list, which costs O(n) gas. For large
  batches, anchor only the root on-chain and keep the digest list in calldata or
  a data-availability layer; the `readingBatch` replay check then needs an
  off-chain or ZK alternative.
- The contract is not audited. Treat it as a reference, not production-ready
  financial infrastructure.
- The Python project does not compile Solidity in CI. Run `forge build` or
  `npx hardhat compile` before deploying.
