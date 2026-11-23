# fogaudit – decentralized CPS data auditing (Algebraic Signature + Circom/Groth16)

Terminal-only demo of the paper's protocol, plus a browser simulator in `ui/`. You play every role:
Client, CSP, Edge device, Proxy, Blockchain. Every step is printed, from the file you give as input to
how it is stored and how it is verified.

The zkSNARKs are real:
* circuits: `zk/circuits/auditlib.circom` (circom 2.1.4, circomlib Poseidon, algebraic signature)
  - C1 `TagCircuit(N,S)`  – tag verification (metadata registration), built for a **batch** of N blocks
  - C2 `PoPCircuit(S)`    – proof of possession (periodic audit)
* proof system: Groth16 over BN254 (snarkjs 0.7). Verification keys are used by the simulated
  smart contract; Solidity verifiers are exported to `build/contracts/`.
* Rust computes Poseidon with `light-poseidon`, which matches circomlib's constants.

## Requirements
* Rust (https://rustup.rs) and Node.js >= 18

## Run
    cd zk && npm install && cd ..
    cargo run --release -- abc.txt                        # any file up to 256 blocks
    cargo run --release -- abc.txt --detail 8             # explain every block and tag
    cargo run --release -- abc.txt --rounds 5 --pct 50
    cargo run --release -- abc.txt --corrupt 1 --pct 100  # edge device loses data -> no valid proof
    cargo run --release -- abc.txt --step                 # press Enter between phases
    cargo run --release -- abc.txt --rebuild              # redo circuit compile + Groth16 setup
    cargo run --release -- abc.txt --sector-bytes 7       # small 28-byte blocks, easier to read

The first run compiles the circuits and runs the Groth16 setup (about 20 s). Results are cached in
`build/`, so later runs take a few seconds. A timing summary is printed at the end of every run.

## Options
    --batch B          blocks per C1 (tag) proof, default 8
    --sector-bytes N   bytes packed into one field element, 1..31, default 31
    --jobs J           C1 batch proofs generated in parallel, default = CPU cores (max 4)
    --o2               compile with circom --O2 (see below), off by default
    --rounds N  --pct P  --corrupt B  --detail N  --step  --rebuild

## Web front end (real runs)
A browser front end that runs the real program for you. Drop a raw file, pick options and press Run: the page
shows the file as blocks, then lights up each protocol stage as the program reaches it, with its live log, the
circuit sizes, every proof and verification result, the blocks each audit challenged, and where the time went.

    cargo build --release                # once
    (cd zk && npm install)               # once
    node web/server.js                   # then open http://127.0.0.1:3000

* One run at a time (runs share the `build/` cache). Uploaded files are kept in `uploads/`.
* Options in the page map to the CLI flags: sector size, C1 batch size, audit rounds, challenged %, "edge loses
  block #" (`--corrupt`), and how many blocks to explain.
* `PORT=8080 node web/server.js` changes the port. The server listens on 127.0.0.1 only. Setting
  `HOST=0.0.0.0` exposes it to your network: it has no login and lets anyone start proof runs, so put it behind
  authentication before putting it on the internet.
* To host it you need a machine with Rust and Node.js (it runs snarkjs and the Rust binary on the server);
  it cannot be hosted as a static site.

## Browser simulator (no install)
Open `ui/fogaudit-flow-lab.html` in any browser. This one needs no install and runs nothing real. It walks a file through split, archive, tag, register,
challenge, prove and verify with an animated role diagram and a protocol log. It uses toy arithmetic in
place of Poseidon and Groth16 (so proof bytes are not real), but its block layout, batching and constraint
counts follow this code.

## Speed: what was slow and what changed
Registration used one C1 circuit over the whole file. Its size grew with the file: a 64-block file
(1792 B in 28-byte blocks) was **48,159 constraints**, which does not fit the shipped 2^14 powers-of-tau,
so a 2^16 file had to be generated (about 10 minutes here), and the Groth16 setup for that circuit had still
not finished after another 9 minutes. Three changes fix this:

1. **31-byte sectors (`--sector-bytes`, default 31).** A field element holds 31 bytes (248 bits) with no
   reduction, but the old code put only 7 bytes in each. C1 cost is per block, so a 1792-byte file drops
   from 64 blocks to 15. Use `--sector-bytes 7` to get the old small blocks back.
2. **Batched C1.** `TagCircuit(N,S)` is now compiled for a batch of `--batch` blocks (default 8, 6,335
   constraints) and a file is registered with ceil(n/batch) proofs of that one circuit. A short last batch is
   padded with all-zero blocks, and the contract pads its public input the same way. The circuit, proving key
   and powers-of-tau no longer depend on the file size, so the setup is done once and cached, the shipped
   `pot14_final.ptau` is always enough, and the old 64-block cap is gone (limit is now 256 blocks).
3. **Cheaper algebraic signature.** `AlgSig` uses Horner's rule (S multiplications instead of 2S-1).
   The value is identical, so tags, hashes and the Rust code are unchanged.

Measured on a 2-core machine, 1792-byte file:

| | before | now |
|---|---|---|
| blocks | 64 | 15 (or 64 with `--sector-bytes 7`) |
| biggest C1 circuit | 48,159 constraints | 6,335 constraints |
| powers of tau | 2^16, generated (~10 min) | 2^14, shipped |
| first run | did not finish (setup over 9 min after the ptau) | about 29 s |
| later runs | – | about 8 s (about 19 s with `--sector-bytes 7`) |
| C1 proving | – | 2.4 s (11.4 s with `--sector-bytes 7`) |

Notes from the measurements:
* `--o2` roughly halves the constraint count (6,335 to 2,621 for 8 blocks), but it makes the one-time setup
  about 4x slower (26 s against 6 s) and proofs were no faster at this size (about 1.3 s either way), so it is
  off by default. It can help if you raise `--batch` so far that the default build no longer fits 2^14.
* `--jobs` runs several batch proofs side by side. On the 2-core test machine it gave no gain because snarkjs
  already uses both cores; it should help on machines with more cores.
* `--batch` can be raised, but a bigger circuit is slower per proof and past about 21 blocks (default build)
  needs a bigger ptau, which is generated automatically and takes minutes.
* C2 proving (about 0.7 s per audit round) is dominated by snarkjs start-up and was not the bottleneck.

## Folders created while running
    csp_storage/<file>/<file>          archival copy at the CSP
    edge_storage/<file>/blocks/*.bin   raw blocks on the edge device
    edge_storage/<file>/tags.txt       index, Poseidon hash, algebraic tag
    edge_storage/<file>/key.secret     edge device's secret AS key K
    build/                             r1cs, wasm, .zkey, vkey.json, proofs, Solidity verifiers

## Honest limitations
* `ptau/pot14_final.ptau` was generated locally with ONE contribution (supports 2^14 constraints).
  Fine for a demo, not a trusted multi-party ceremony.
* The blockchain and smart contracts are simulated in Rust; the Groth16 verification they do is real.
* C1 is now several proofs per file. Each is bound to the contract's own stored hashes and the submitted tags,
  but the demo does not add anything beyond that (for example no aggregation of the batch proofs).
* Larger sectors mean coarser blocks: one changed byte invalidates a 124-byte block instead of a 28-byte one,
  and a given challenge percentage covers fewer blocks of a small file.
