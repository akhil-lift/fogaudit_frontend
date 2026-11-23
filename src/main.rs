// fogaudit: terminal walkthrough of "Decentralized CPS-Data Auditing using
// Algebraic Signature and zkSNARK".
//
// One process plays every role (Client, CSP, Edge device, Proxy, Blockchain) and
// prints every step.  The zkSNARKs are REAL: Circom circuits (zk/circuits),
// Groth16 over BN254 (snarkjs), circomlib Poseidon (light-poseidon on the Rust side).

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

// ───────────────────────── printing ─────────────────────────
const RST: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn colour(role: &str) -> &'static str {
    match role {
        "CSP" => "\x1b[36m",
        "EDGE" => "\x1b[33m",
        "PROXY" => "\x1b[35m",
        "CHAIN" => "\x1b[34m",
        "CLIENT" => "\x1b[32m",
        _ => "\x1b[0m",
    }
}
static mut STEP_MODE: bool = false;

fn say(role: &str, msg: &str) {
    println!("{}[{:<6}]{} {}", colour(role), role, RST, msg);
}
fn banner(title: &str) {
    println!("\n{}\x1b[97m══════════ {} ══════════{}", BOLD, title, RST);
    pause();
}
fn ok(msg: &str) {
    println!("          \x1b[32m✔ {}{}", msg, RST);
}
fn bad(msg: &str) {
    println!("          \x1b[31m✘ {}{}", msg, RST);
}
fn note(msg: &str) {
    println!("          {}{}{}", DIM, msg, RST);
}
fn pause() {
    unsafe {
        if STEP_MODE {
            print!("{}   (press Enter to continue){}", DIM, RST);
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().read_line(&mut s).ok();
        }
    }
}

// ───────────────────────── BN254 scalar field helpers ─────────────────────────
// Same field as the Circom circuits (snarkjs "bn128").
fn dec(x: &Fr) -> String {
    x.into_bigint().to_string()
}
fn hexfull(x: &Fr) -> String {
    x.into_bigint().to_bytes_be().iter().map(|b| format!("{:02x}", b)).collect()
}
fn hx(x: &Fr) -> String {
    format!("0x{}…", &hexfull(x)[..12])
}
fn hxs(v: &[Fr]) -> String {
    let parts: Vec<String> = v.iter().take(3).map(hx).collect();
    if v.len() > 3 {
        format!("[{}, … ({} total)]", parts.join(", "), v.len())
    } else {
        format!("[{}]", parts.join(", "))
    }
}
fn low64(x: &Fr) -> u64 {
    x.into_bigint().0[0]
}

// circomlib-compatible Poseidon (same constants as circomlib's Poseidon(n) template)
fn pos(inputs: &[Fr]) -> Fr {
    let mut p = Poseidon::<Fr>::new_circom(inputs.len()).expect("poseidon params");
    p.hash(inputs).expect("poseidon hash")
}

fn fill_random(buf: &mut [u8]) {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    // fallback (e.g. Windows): time-seeded xorshift – fine for a demo
    let mut x = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 24) as u8;
    }
}
fn rand_fr() -> Fr {
    loop {
        let mut b = [0u8; 32];
        fill_random(&mut b);
        let x = Fr::from_le_bytes_mod_order(&b);
        if !x.is_zero() {
            return x;
        }
    }
}

// ───────────────────────── Algebraic signature ─────────────────────────
// tau = AS_K(m) = sum_{j=1..s} b_j * K^j
fn alg_sig(k: Fr, block: &[Fr]) -> Fr {
    let mut acc = Fr::zero();
    let mut kp = Fr::one();
    for b in block {
        kp *= k;
        acc += *b * kp;
    }
    acc
}

// ───────────────────────── PRFs (challenge expansion) ─────────────────────────
fn prf1(seed: Fr, c: usize, n: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = Vec::new();
    let mut ctr = 0u64;
    while idx.len() < c {
        let i = (low64(&pos(&[seed, Fr::from(1u64), Fr::from(ctr)])) % n as u64) as usize;
        ctr += 1;
        if !idx.contains(&i) {
            idx.push(i);
        }
    }
    idx.sort();
    idx
}
fn prf2(seed: Fr, c: usize) -> Vec<Fr> {
    (0..c as u64)
        .map(|k| {
            let v = pos(&[seed, Fr::from(2u64), Fr::from(k)]);
            if v.is_zero() { Fr::one() } else { v }
        })
        .collect()
}
fn aggregate(blocks: &[Vec<Fr>], idx: &[usize], v: &[Fr]) -> Vec<Fr> {
    let mut r = vec![Fr::zero(); SECTORS];
    for (pos_, &i) in idx.iter().enumerate() {
        for j in 0..SECTORS {
            r[j] += v[pos_] * blocks[i][j];
        }
    }
    r
}
fn agg_tag(tags: &[Fr], idx: &[usize], v: &[Fr]) -> Fr {
    let mut t = Fr::zero();
    for (pos_, &i) in idx.iter().enumerate() {
        t += v[pos_] * tags[i];
    }
    t
}

// ───────────────────────── file → blocks → sectors ─────────────────────────
//
// Circuit parameters that decide proving cost (see README "Speed"):
//   SECTORS        s, sectors per block. Fixed at compile time because the circuits are
//                  built for it (Poseidon(s) per block).
//   sector_bytes() bytes packed into ONE field element (sector). Runtime option
//                  --sector-bytes, default 31 (248 bits < the 254-bit field, so no
//                  reduction ever happens).  The old demo used 7, which made a 1792-byte
//                  file 64 blocks; with 31 it is 15 blocks, and C1 cost is per block.
//   batch          blocks per C1 proof (--batch, default 8).  The tag circuit is built for
//                  a batch, not for the whole file, so it is compiled and set up once.
const SECTORS: usize = 4; // s
const DEFAULT_SECTOR_BYTES: usize = 31;
const DEFAULT_BATCH: usize = 8;
const MAX_BLOCKS: usize = 256;
static SECTOR_BYTES: AtomicUsize = AtomicUsize::new(DEFAULT_SECTOR_BYTES);
// --o2: compile circuits with circom --O2 (about 60% fewer constraints, but a ~4x slower one-time Groth16
// setup and, measured at these sizes, no faster proofs).  Off by default.
static OPT2: AtomicBool = AtomicBool::new(false);
fn sector_bytes() -> usize {
    SECTOR_BYTES.load(Ordering::Relaxed)
}
fn block_bytes() -> usize {
    SECTORS * sector_bytes()
}

fn split_blocks(data: &[u8]) -> Vec<Vec<Fr>> {
    let mut out = vec![];
    for chunk in data.chunks(block_bytes()) {
        let mut padded = chunk.to_vec();
        padded.resize(block_bytes(), 0);
        let mut blk = vec![];
        for sec in padded.chunks(sector_bytes()) {
            // little-endian integer; <= 31 bytes so it is always below the field modulus
            blk.push(Fr::from_le_bytes_mod_order(sec));
        }
        out.push(blk);
    }
    if out.is_empty() {
        out.push(vec![Fr::zero(); SECTORS]);
    }
    out
}

fn esc(b: &[u8]) -> String {
    b.iter()
        .map(|c| if c.is_ascii_graphic() || *c == b' ' { (*c as char).to_string() } else { format!("\\x{:02x}", c) })
        .collect()
}
fn hexbytes(b: &[u8]) -> String {
    b.iter().map(|c| format!("{:02x}", c)).collect::<Vec<_>>().join(" ")
}

fn explain_blocks(data: &[u8], blocks: &[Vec<Fr>], show: usize) {
    let bb = block_bytes();
    for (i, chunk) in data.chunks(bb).enumerate().take(show) {
        note(&format!("┌─ block m_{}  (file bytes {}..{})", i, i * bb, i * bb + chunk.len()));
        note(&format!("│ text    : \"{}\"", esc(chunk)));
        let mut padded = chunk.to_vec();
        if padded.len() < bb {
            note(&format!("│ (last block is short → zero-padded from {} to {} bytes)", padded.len(), bb));
            padded.resize(bb, 0);
        }
        for (j, sec) in padded.chunks(sector_bytes()).enumerate() {
            let hex = hexbytes(sec);
            let hex = if hex.len() > 48 { format!("{} …", &hex[..48]) } else { hex };
            let val = dec(&blocks[i][j]);
            let val = if val.len() > 30 { format!("{}…", &val[..30]) } else { val };
            note(&format!("│ sector b_{}{} = [{}]  → little-endian integer = {}", i, j + 1, hex, val));
        }
        note(&format!("└─ m_{} = ⟨{}⟩", i, blocks[i].iter().map(dec).collect::<Vec<_>>().join(", ")));
    }
    if blocks.len() > show {
        note(&format!("… {} more blocks built the same way (use --detail N to see more)", blocks.len() - show));
    }
}

fn explain_tag(k: Fr, block: &[Fr], i: usize) {
    note(&format!("┌─ tag for block m_{}:  τ_{} = Σ b_{}j · K^j  (mod r),  K = {}", i, i, i, hx(&k)));
    let mut kp = Fr::one();
    let mut acc = Fr::zero();
    for (j, b) in block.iter().enumerate() {
        kp *= k;
        let term = *b * kp;
        acc += term;
        note(&format!("│ j={}: b_{}{} · K^{} = {} · {} = {}   (running sum {})", j + 1, i, j + 1, j + 1, dec(b), hx(&kp), hx(&term), hx(&acc)));
    }
    note(&format!("└─ τ_{} = {}", i, hx(&acc)));
}

fn explain_aggregation(tags: &[Fr], idx: &[usize], v: &[Fr], k: Fr, magg: &[Fr], tau_agg: Fr, show: usize) {
    let show = show.max(2);
    for (p, &i) in idx.iter().enumerate().take(show) {
        note(&format!("challenged block m_{}:  v = {}   τ_{} = {}", i, hx(&v[p]), i, hx(&tags[i])));
    }
    if idx.len() > show {
        note(&format!("… {} more challenged blocks", idx.len() - show));
    }
    for j in 0..SECTORS {
        note(&format!("r_{} = Σ_k v_k · b_k{}  (mod r) over {} blocks = {}", j + 1, j + 1, idx.len(), hx(&magg[j])));
    }
    note(&format!("m_agg = ⟨r_1..r_{}⟩", SECTORS));
    note(&format!("τ_agg  = Σ_k v_k · τ_k  (mod r) = {}", hx(&tau_agg)));
    let lhs = alg_sig(k, magg);
    note(&format!("homomorphic identity: AS_K(m_agg) = Σ_j r_j·K^j = {}", hx(&lhs)));
    if lhs == tau_agg {
        note("   AS_K(m_agg) == τ_agg  ✔  (aggregated data matches aggregated tags)");
    } else {
        note("   AS_K(m_agg) != τ_agg  ✘  (data on disk no longer matches the registered tags)");
    }
}

// ───────────────────────── edge-device storage on disk ─────────────────────────
fn save_storage(name: &str, data: &[u8], hf: &[Fr], tags: &[Fr], k: Fr) -> std::io::Result<()> {
    let csp = format!("csp_storage/{}", name);
    let edge = format!("edge_storage/{}", name);
    std::fs::create_dir_all(&csp)?;
    std::fs::create_dir_all(format!("{}/blocks", edge))?;
    std::fs::write(format!("{}/{}", csp, name), data)?;
    for (i, chunk) in data.chunks(block_bytes()).enumerate() {
        std::fs::write(format!("{}/blocks/block_{:04}.bin", edge, i), chunk)?;
    }
    let mut t = String::from("# index, block_hash(Poseidon), tag(AS)\n");
    for i in 0..hf.len() {
        t.push_str(&format!("{}, {}, {}\n", i, hexfull(&hf[i]), hexfull(&tags[i])));
    }
    std::fs::write(format!("{}/tags.txt", edge), t)?;
    std::fs::write(format!("{}/key.secret", edge), format!("{}\n", hexfull(&k)))?;
    Ok(())
}
fn load_blocks(name: &str, n: usize) -> Vec<Vec<Fr>> {
    (0..n)
        .map(|i| {
            let bytes = std::fs::read(format!("edge_storage/{}/blocks/block_{:04}.bin", name, i)).unwrap_or_default();
            split_blocks(&bytes).remove(0)
        })
        .collect()
}

// ───────────────────────── Circom / snarkjs tooling ─────────────────────────
const SNARKJS: &str = "zk/node_modules/snarkjs/build/cli.cjs";
const CIRCOM: &str = "zk/node_modules/circom2/cli.js";
const LIBPATH: &str = "zk/node_modules";
const BUILD: &str = "build";

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            if it.peek() == Some(&'[') {
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// run a node-based tool; Ok(output) on exit 0, Err(output) otherwise
fn tool(name: &str, js: &str, args: &[&str]) -> Result<String, String> {
    let t = Instant::now();
    let out = Command::new("node").arg(js).args(args).output();
    let secs = t.elapsed().as_secs_f32();
    let short: Vec<String> = args
        .iter()
        .map(|a| a.strip_prefix("build/").map(|s| format!("…/{}", s.rsplit('/').next().unwrap_or(s))).unwrap_or(a.to_string()))
        .collect();
    match out {
        Err(e) => Err(format!("cannot start node ({}). Is Node.js installed? Did you run 'npm install' in zk/ ?", e)),
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            let text = strip_ansi(&text);
            note(&format!("$ {} {}   [{:.1}s]", name, short.join(" "), secs));
            if o.status.success() { Ok(text) } else { Err(text) }
        }
    }
}
fn snarkjs(args: &[&str]) -> Result<String, String> {
    tool("snarkjs", SNARKJS, args)
}

fn num_after(text: &str, key: &str) -> usize {
    text.find(key)
        .map(|i| text[i + key.len()..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn show_file(path: &str) {
    if let Ok(s) = std::fs::read_to_string(path) {
        for l in s.lines() {
            note(&format!("│ {}", l));
        }
    }
}

struct Circuit {
    wasm: String,
    zkey: String,
    vkey: String,
    constraints: usize,
    pubs: usize,
}

// CSP: compile one circuit → r1cs + wasm
fn compile_circuit(label: &str, dir: &str, main_name: &str, wrapper: &str) -> Result<(String, usize, usize), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let src = format!("{}/{}.circom", dir, main_name);
    std::fs::write(&src, wrapper).map_err(|e| e.to_string())?;
    say("CSP", &format!("{}: writes the main component", label));
    show_file(&src);
    let r1cs = format!("{}/{}.r1cs", dir, main_name);
    let wasm = format!("{}/{}_js/{}.wasm", dir, main_name, main_name);
    if Path::new(&r1cs).exists() && Path::new(&wasm).exists() {
        note("(cached) r1cs + wasm already compiled for this circuit size");
    } else {
        let o2 = OPT2.load(Ordering::Relaxed);
        say("CSP", &format!("{}: compiles with circom{} → R1CS constraint system + WASM witness generator", label, if o2 { " --O2" } else { "" }));
        let mut a: Vec<&str> = vec![&src, "--r1cs", "--wasm"];
        if o2 {
            a.push("--O2");
        }
        a.extend_from_slice(&["-l", LIBPATH, "-o", dir]);
        tool("circom2", CIRCOM, &a)?;
    }
    let info = snarkjs(&["r1cs", "info", &r1cs])?;
    let cons = num_after(&info, "# of Constraints:");
    let pubs = num_after(&info, "# of Public Inputs:");
    let privs = num_after(&info, "# of Private Inputs:");
    ok(&format!("{}: {} constraints, {} public inputs, {} private inputs", label, cons, pubs, privs));
    Ok((wasm, cons, pubs))
}

fn ptau_for(needed_power: usize) -> Result<String, String> {
    std::fs::create_dir_all("ptau").ok();
    for p in needed_power..=22 {
        let f = format!("ptau/pot{}_final.ptau", p);
        if Path::new(&f).exists() {
            note(&format!("using existing powers-of-tau file {} (supports up to 2^{} constraints)", f, p));
            return Ok(f);
        }
    }
    let p = needed_power.max(10);
    say("CSP", &format!("no powers-of-tau file large enough – generating 2^{} (one-time, can take a few minutes)…", p));
    let ps = p.to_string();
    let (f0, f1, ff) = (format!("ptau/pot{}_0000.ptau", p), format!("ptau/pot{}_0001.ptau", p), format!("ptau/pot{}_final.ptau", p));
    snarkjs(&["powersoftau", "new", "bn128", &ps, &f0])?;
    let ent = format!("-e=fogaudit-demo-entropy-{}", low64(&rand_fr()));
    snarkjs(&["powersoftau", "contribute", &f0, &f1, "--name=fogaudit demo", &ent])?;
    snarkjs(&["powersoftau", "prepare", "phase2", &f1, &ff])?;
    std::fs::remove_file(&f0).ok();
    std::fs::remove_file(&f1).ok();
    Ok(ff)
}

fn groth16_setup(label: &str, dir: &str, tag: &str, r1cs: &str, ptau: &str, wasm: String, cons: usize, pubs: usize) -> Result<Circuit, String> {
    let zkey = format!("{}/{}_final.zkey", dir, tag);
    let vkey = format!("{}/{}_vkey.json", dir, tag);
    if Path::new(&zkey).exists() && Path::new(&vkey).exists() {
        note(&format!("(cached) {} proving key + verification key already exist", label));
    } else {
        say("CSP", &format!("{}: Groth16 Setup(1^λ, C) → (pk, vk)", label));
        let z0 = format!("{}/{}_0000.zkey", dir, tag);
        snarkjs(&["groth16", "setup", r1cs, ptau, &z0])?;
        let ent = format!("-e=fogaudit-csp-entropy-{}", low64(&rand_fr()));
        snarkjs(&["zkey", "contribute", &z0, &zkey, "--name=CSP phase-2", &ent])?;
        snarkjs(&["zkey", "export", "verificationkey", &zkey, &vkey])?;
        std::fs::remove_file(&z0).ok();
        std::fs::create_dir_all(format!("{}/contracts", BUILD)).ok();
        let sol = format!("{}/contracts/{}_Verifier.sol", BUILD, tag);
        snarkjs(&["zkey", "export", "solidityverifier", &zkey, &sol])?;
        ok(&format!("Solidity verifier contract exported: {}", sol));
    }
    Ok(Circuit { wasm, zkey, vkey, constraints: cons, pubs })
}

fn json_fr_arr(v: &[Fr]) -> String {
    format!("[{}]", v.iter().map(|x| format!("\"{}\"", dec(x))).collect::<Vec<_>>().join(","))
}

// Edge: build witness + Groth16 proof. Err(message) if the constraints are not satisfied.
fn prove(circ: &Circuit, input_json: &str, tag: &str) -> Result<String, String> {
    std::fs::create_dir_all(format!("{}/work", BUILD)).ok();
    let inp = format!("{}/work/{}_input.json", BUILD, tag);
    let proof = format!("{}/work/{}_proof.json", BUILD, tag);
    let public = format!("{}/work/{}_public.json", BUILD, tag);
    std::fs::write(&inp, input_json).map_err(|e| e.to_string())?;
    match snarkjs(&["groth16", "fullprove", &inp, &circ.wasm, &circ.zkey, &proof, &public]) {
        Ok(_) => Ok(proof),
        Err(e) => {
            let lines: Vec<&str> = e.lines().filter(|l| l.contains("Assert Failed")).take(1).collect();
            Err(lines.join(" | ").trim().to_string())
        }
    }
}

// Prove every C1 batch. Each proof is an independent snarkjs process, so `jobs` of them
// run side by side (the work queue is a shared counter).
fn prove_batches(circ: &Circuit, inputs: &[String], jobs: usize) -> Result<Vec<String>, String> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Result<String, String>>>> = Mutex::new((0..inputs.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..jobs.min(inputs.len()).max(1) {
            s.spawn(|| loop {
                let t = next.fetch_add(1, Ordering::SeqCst);
                if t >= inputs.len() {
                    break;
                }
                let r = prove(circ, &inputs[t], &format!("c1_reg_b{}", t));
                results.lock().unwrap()[t] = Some(r);
            });
        }
    });
    results.into_inner().unwrap().into_iter().map(|r| r.unwrap()).collect()
}

fn json_first(s: &str, key: &str) -> String {
    (|| {
        let i = s.find(&format!("\"{}\"", key))?;
        let rest = &s[i..];
        let a = rest.find('"')? ; // opening quote of key (skip)
        let rest2 = &rest[a + 1..];
        let b = rest2.find('"')?;
        let rest3 = &rest2[b + 1..];
        let c = rest3.find('[')?;
        let rest4 = &rest3[c..];
        let d = rest4.find('"')?;
        let rest5 = &rest4[d + 1..];
        let e = rest5.find('"')?;
        Some(rest5[..e].to_string())
    })()
    .unwrap_or_default()
}
fn show_proof(path: &str) {
    if let Ok(s) = std::fs::read_to_string(path) {
        let a = json_first(&s, "pi_a");
        let short = if a.len() > 18 { format!("{}…", &a[..18]) } else { a };
        note(&format!("proof.json: {} bytes, Groth16/bn128, π_A.x = {}  (constant size, independent of file size)", s.len(), short));
    }
}

// What a smart contract does: build the public inputs itself and run Groth16 Verify.
fn snark_verify(vkey: &str, public: &[Fr], proof_path: &str, tag: &str) -> bool {
    std::fs::create_dir_all(format!("{}/work", BUILD)).ok();
    let pubf = format!("{}/work/{}_public_by_contract.json", BUILD, tag);
    std::fs::write(&pubf, json_fr_arr(public)).ok();
    match snarkjs(&["groth16", "verify", vkey, &pubf, proof_path]) {
        Ok(out) => {
            let res = out.contains("OK!");
            note(&format!("snarkjs: {}", out.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim()));
            res
        }
        Err(e) => {
            note(&format!("snarkjs: {}", e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("error").trim()));
            false
        }
    }
}

// ───────────────────────── Blockchain + smart contracts ─────────────────────────
struct FileEntry {
    id_edge: String,
    hk: Fr,
    hf: Vec<Fr>,
    tags: Option<Vec<Fr>>,
}
struct Chain {
    vk1: String,
    vk2: String,
    files: HashMap<u64, FileEntry>,
    seeds: HashMap<u64, Fr>,
    next_chal: u64,
    audit_log: Vec<(u64, u64, bool)>,
    balances: HashMap<String, i64>,
    c: usize,
    n_blocks: usize,
    batch: usize,    // blocks per C1 proof
    zero_hash: Fr,   // Poseidon of an all-zero block, a constant known to the contract
}
// public input x1 of one C1 batch proof: {H_K, H_F[batch], T_F[batch]}.
// A last, shorter batch is padded with all-zero blocks (hash = zero_hash, tag = 0).
fn batch_x1(hk: Fr, hf: &[Fr], tf: &[Fr], t: usize, batch: usize, zero_hash: Fr) -> Vec<Fr> {
    let mut x = vec![hk];
    let (lo, hi) = (t * batch, ((t + 1) * batch).min(hf.len()));
    for i in lo..lo + batch {
        x.push(if i < hi { hf[i] } else { zero_hash });
    }
    for i in lo..lo + batch {
        x.push(if i < hi { tf[i] } else { Fr::zero() });
    }
    x
}
impl Chain {
    // Algorithm 1
    fn register_file(&mut self, caller: &str, id_f: u64, id_edge: &str, hk: Fr, hf: Vec<Fr>) -> Result<(), String> {
        if caller != "CSP" {
            return Err("NO AUTHORIZATION".into());
        }
        if let Some(e) = self.files.get_mut(&id_f) {
            e.id_edge = id_edge.into();
            e.hk = hk;
            e.hf = hf;
        } else {
            self.files.insert(id_f, FileEntry { id_edge: id_edge.into(), hk, hf, tags: None });
        }
        Ok(())
    }
    // Algorithm 2
    fn register_metadata(&mut self, id_f: u64, tf: Vec<Fr>, proofs: &[String], tag: &str) -> Result<(), String> {
        let e = self.files.get(&id_f).ok_or("unknown file")?;
        if tf.len() != e.hf.len() {
            return Err("InvalidTags".into());
        }
        let nb = (e.hf.len() + self.batch - 1) / self.batch;
        if proofs.len() != nb {
            return Err("WrongNumberOfProofs".into());
        }
        note(&format!(
            "contract splits H_F/T_F into {} batch(es) of {} blocks and builds x1 = {{H_K, H_F[{b}], T_F[{b}]}} = {} field elements per batch",
            nb, self.batch, 1 + 2 * self.batch, b = self.batch
        ));
        for (t, p) in proofs.iter().enumerate() {
            let x1 = batch_x1(e.hk, &e.hf, &tf, t, self.batch, self.zero_hash);
            if !snark_verify(&self.vk1, &x1, p, &format!("{}_b{}", tag, t)) {
                return Err("InvalidTags".into());
            }
        }
        self.files.get_mut(&id_f).unwrap().tags = Some(tf);
        Ok(())
    }
    fn request_seed(&mut self) -> (u64, Fr) {
        self.next_chal += 1;
        let seed = rand_fr();
        self.seeds.insert(self.next_chal, seed);
        (self.next_chal, seed)
    }
    // Algorithm 3
    fn verify_pop(&mut self, caller: &str, id_f: u64, chal: u64, h_magg: Fr, proof_path: &str, tag: &str, log: bool) -> Result<bool, String> {
        if caller != "PROXY" {
            return Err("NO AUTHORIZATION".into());
        }
        let seed = *self.seeds.get(&chal).ok_or("unknown challenge")?;
        let idx = prf1(seed, self.c, self.n_blocks);
        let v = prf2(seed, self.c);
        let e = self.files.get(&id_f).ok_or("unknown file")?;
        let tf = e.tags.as_ref().ok_or("tags not registered")?;
        let tau = agg_tag(tf, &idx, &v);
        let x2 = [e.hk, tau, h_magg];
        if log {
            note(&format!("contract looks up its own seed S = {} for Chal_id {}", hx(&seed), chal));
            note(&format!("contract recomputes I = PRF1(S,c) = {:?}", idx));
            note(&format!("contract recomputes V = PRF2(S,c) = {}", hxs(&v)));
            note(&format!("contract reads H_K = {} and T_F from its storage", hx(&e.hk)));
            note(&format!("contract computes τ_agg = Σ v_k·τ_k = {}   (it never sees the data)", hx(&tau)));
            note(&format!("public input x2 = {{H_K, τ_agg, H_magg}} = {{{}, {}, {}}}", hx(&e.hk), hx(&tau), hx(&h_magg)));
            note("contract runs Groth16 Verify(vk2, x2, π2) …");
        }
        let res = snark_verify(&self.vk2, &x2, proof_path, tag);
        self.audit_log.push((id_f, chal, res));
        Ok(res)
    }
    fn bal(&self, who: &str) -> i64 {
        *self.balances.get(who).unwrap_or(&0)
    }
}

const FORGED_PROOF: &str = r#"{"pi_a":["1","2","1"],"pi_b":[["10857046999023057135944570762232829481370756359578518086990519993285655852781","11559732032986387107991004021392285783925812861821192530917403151452391805634"],["8495653923123431417604973247489272438418190587263600148770280649306958101930","4082367875863433681332203403145435568316851327593401208105741076214120093531"],["1","0"]],"pi_c":["1","2","1"],"protocol":"groth16","curve":"bn128"}"#;

fn usage() {
    println!("usage: fogaudit <file> [--rounds N] [--pct P] [--corrupt BLOCK] [--detail N] [--step] [--rebuild]");
    println!("                      [--batch B] [--sector-bytes N] [--jobs J] [--o2]");
    println!("  --o2           compile with circom --O2: fewer constraints, but slower setup and no faster proofs here");
    println!("  --batch B      blocks per C1 (tag) proof; the circuit is built once for B blocks (default {})", DEFAULT_BATCH);
    println!("  --sector-bytes N  bytes packed per field element, 1..=31 (default {}; use 7 for small, easy-to-read blocks)", DEFAULT_SECTOR_BYTES);
    println!("  --jobs J       C1 batch proofs generated in parallel (default: number of CPU cores, max 4)");
    println!("  --rounds N     number of audit rounds (default 3)");
    println!("  --pct P        % of blocks challenged per round (default 50)");
    println!("  --corrupt B    after registration, silently corrupt block B on the edge device");
    println!("  --detail N     explain block/tag construction for the first N blocks (default 3)");
    println!("  --step         pause after each phase (press Enter)");
    println!("  --rebuild      delete compiled circuits + keys in build/ and redo the zkSNARK setup");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1] == "--help" {
        usage();
        return;
    }
    let path = &args[1];
    let mut rounds = 3usize;
    let mut pct = 50usize;
    let mut corrupt: Option<usize> = None;
    let mut detail = 3usize;
    let mut rebuild = false;
    let mut batch = DEFAULT_BATCH;
    let mut jobs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(4);
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--batch" => { batch = args[i + 1].parse().unwrap(); i += 1; }
            "--o2" => OPT2.store(true, Ordering::Relaxed),
            "--jobs" => { jobs = args[i + 1].parse().unwrap(); i += 1; }
            "--sector-bytes" => {
                let sb: usize = args[i + 1].parse().unwrap();
                if sb == 0 || sb > 31 {
                    eprintln!("--sector-bytes must be 1..=31 (31 bytes = 248 bits fit below the 254-bit field)");
                    return;
                }
                SECTOR_BYTES.store(sb, Ordering::Relaxed);
                i += 1;
            }
            "--rounds" => { rounds = args[i + 1].parse().unwrap(); i += 1; }
            "--pct" => { pct = args[i + 1].parse().unwrap(); i += 1; }
            "--corrupt" => { corrupt = Some(args[i + 1].parse().unwrap()); i += 1; }
            "--detail" => { detail = args[i + 1].parse().unwrap(); i += 1; }
            "--step" => unsafe { STEP_MODE = true },
            "--rebuild" => rebuild = true,
            _ => { usage(); return; }
        }
        i += 1;
    }
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => { eprintln!("cannot read {}: {}", path, e); return; }
    };
    if !Path::new(SNARKJS).exists() || !Path::new(CIRCOM).exists() {
        eprintln!("zkSNARK toolchain missing. Run:  cd zk && npm install   (needs Node.js >= 18)");
        return;
    }
    let blocks = split_blocks(&data);
    let n = blocks.len();
    if batch == 0 {
        eprintln!("--batch must be at least 1");
        return;
    }
    if n > MAX_BLOCKS {
        eprintln!("file has {} blocks; this demo supports at most {} blocks ({} bytes) with --sector-bytes {}.", n, MAX_BLOCKS, MAX_BLOCKS * block_bytes(), sector_bytes());
        return;
    }
    let t_total = Instant::now();
    if rebuild {
        std::fs::remove_dir_all(BUILD).ok();
    }

    println!("{}fogaudit – decentralized CPS data auditing (Algebraic Signature + Circom/Groth16 + smart contracts){}", BOLD, RST);
    println!("file: {}  ({} bytes)   field: BN254 scalar field (r ≈ 2^254)", path, data.len());

    // ───────────── Phase 0: SLA ─────────────
    banner("PHASE 0 · SLA between CLIENT and CSP");
    let mut balances = HashMap::new();
    balances.insert("CLIENT".to_string(), 1000i64);
    balances.insert("CSP".to_string(), 1000i64);
    say("CLIENT", "signs SLA with CSP: audit threshold = 90% success, reward = 50 tokens, penalty = 100 tokens");
    say("CLIENT", "stakes 1000 tokens");
    say("CSP", "stakes 1000 tokens");

    // ───────────── Phase 1: Setup (real Circom + Groth16) ─────────────
    banner("PHASE 1 · SETUP – Circom circuits + Groth16 keys  (steps 1a, 1b, 2)");
    say("CSP", "the two circuits live in zk/circuits/auditlib.circom (circom 2.1.4, circomlib Poseidon):");
    show_file("zk/circuits/auditlib.circom");
    let t_setup = Instant::now();
    // C1 depends only on (batch, SECTORS), never on the file size, so it is compiled and set up once and cached.
    let sfx = if OPT2.load(Ordering::Relaxed) { "_o2" } else { "" };
    let c1_dir = format!("{}/c1_b{}_s{}{}", BUILD, batch, SECTORS, sfx);
    let c2_dir = format!("{}/c2_s{}{}", BUILD, SECTORS, sfx);
    let c1_wrap = format!("pragma circom 2.1.4;\ninclude \"../../zk/circuits/auditlib.circom\";\ncomponent main {{public [HK, HF, TF]}} = TagCircuit({}, {});\n", batch, SECTORS);
    let c2_wrap = format!("pragma circom 2.1.4;\ninclude \"../../zk/circuits/auditlib.circom\";\ncomponent main {{public [HK, tauAgg, Hmagg]}} = PoPCircuit({});\n", SECTORS);
    let (wasm1, cons1, pubs1) = compile_circuit(&format!("C1 (tags, batch of {} blocks)", batch), &c1_dir, "c1_main", &c1_wrap).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    let (wasm2, cons2, pubs2) = compile_circuit("C2 (proof of possession)", &c2_dir, "c2_main", &c2_wrap).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    let mut power = 8usize;
    while (1usize << power) < cons1.max(cons2) + pubs1.max(pubs2) + 1 {
        power += 1;
    }
    say("CSP", &format!("needs a powers-of-tau file with 2^{} ≥ {} constraints", power, cons1.max(cons2)));
    let ptau = ptau_for(power).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    note("(demo note: this ptau was made by a single local contribution, NOT a public multi-party ceremony)");
    let c1 = groth16_setup("C1", &c1_dir, "c1", &format!("{}/c1_main.r1cs", c1_dir), &ptau, wasm1, cons1, pubs1).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    let c2 = groth16_setup("C2", &c2_dir, "c2", &format!("{}/c2_main.r1cs", c2_dir), &ptau, wasm2, cons2, pubs2).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1) });
    say("CHAIN", "(step 1a) contracts deployed with verification keys vk1, vk2 embedded:");
    note(&format!("vk1 = {}  ({} constraints, {} public inputs)", c1.vkey, c1.constraints, c1.pubs));
    note(&format!("vk2 = {}  ({} constraints, {} public inputs)", c2.vkey, c2.constraints, c2.pubs));
    say("CSP", "(step 1b) sends proving keys pk1, pk2 (.zkey) and witness generators (.wasm) to the edge device over TLS");
    note(&format!("pk1 = {}", c1.zkey));
    note(&format!("pk2 = {}", c2.zkey));
    let k = rand_fr();
    let hk = pos(&[k]);
    say("EDGE", &format!("generates secret AS key K = {}  (never leaves the device)", hx(&k)));
    say("EDGE", &format!("H_K = Poseidon(K) = {}", hx(&hk)));
    say("EDGE", "(step 2) sends H_K to CSP");
    let setup_secs = t_setup.elapsed().as_secs_f32();

    // ───────────── Phase 2: File registration ─────────────
    banner("PHASE 2 · FILE REGISTRATION by CSP  (step 3, Algorithm 1)");
    let fname = Path::new(path).file_name().unwrap().to_string_lossy().to_string();
    say("CLIENT", &format!("uploads \"{}\" ({} bytes) to the CSP", fname, data.len()));
    let preview = &data[..data.len().min(120)];
    note(&format!("content preview: \"{}\"{}", esc(preview), if data.len() > 120 { " …" } else { "" }));
    say("CSP", &format!("receives \"{}\" and keeps the archival copy in csp_storage/{}/", fname, fname));
    let c = ((n * pct + 99) / 100).clamp(1, n);
    say("CSP", &format!("splits file into n = {} blocks of {} bytes = {} sectors × {} bytes each", n, block_bytes(), SECTORS, sector_bytes()));
    note(&format!("each {}-byte sector is read as a little-endian integer, so it is an element of the BN254 scalar field", sector_bytes()));
    explain_blocks(&data, &blocks, detail);
    let hf: Vec<Fr> = blocks.iter().map(|b| pos(b)).collect();
    say("CSP", "hashes every block:  hm_i = Poseidon(sectors of m_i)   (circomlib-compatible Poseidon)");
    for (i, h) in hf.iter().enumerate().take(detail) {
        note(&format!("hm_{} = Poseidon(m_{}) = {}", i, i, hx(h)));
    }
    say("CSP", &format!("H_F = ⟨hm_0 … hm_{}⟩ = {}", n - 1, hxs(&hf)));
    say("CSP", "transfers file to edge device (TLS) – edge keeps its own copy");
    let id_f = low64(&pos(&[Fr::from(data.len() as u64), hf[0]])) % 1_000_000;
    let mut chain = Chain {
        vk1: c1.vkey.clone(),
        vk2: c2.vkey.clone(),
        files: HashMap::new(), seeds: HashMap::new(), next_chal: 0,
        audit_log: vec![], balances, c, n_blocks: n,
        batch,
        zero_hash: pos(&vec![Fr::zero(); SECTORS]),
    };
    say("CSP", &format!("calls registerFile(ID_F={}, ID_edge=EDGE-1, H_K, H_F)", id_f));
    match chain.register_file("EDGE-1", id_f, "EDGE-1", hk, hf.clone()) {
        Err(e) => { say("CHAIN", "registerFile called by EDGE-1 …"); bad(&format!("ABORT \"{}\"  (only CSP may register)", e)); }
        Ok(_) => unreachable!(),
    }
    chain.register_file("CSP", id_f, "EDGE-1", hk, hf.clone()).unwrap();
    say("CHAIN", "registerFile called by CSP …");
    ok("stored ⟨ID_F, ID_edge, H_K, H_F⟩, EMIT FileRegistered");

    // ───────────── Phase 3: Metadata registration ─────────────
    banner("PHASE 3 · METADATA REGISTRATION by EDGE  (step 4, Algorithm 2)");
    let edge_blocks = blocks.clone();
    let tf: Vec<Fr> = edge_blocks.iter().map(|b| alg_sig(k, b)).collect();
    say("EDGE", "receives the file from CSP and generates an algebraic-signature tag for every block");
    for (i, b) in edge_blocks.iter().enumerate().take(detail) {
        explain_tag(k, b, i);
    }
    if n > detail {
        note(&format!("… remaining {} tags computed the same way", n - detail));
    }
    say("EDGE", &format!("T_F = ⟨τ_0 … τ_{}⟩ = {}", n - 1, hxs(&tf)));
    say("EDGE", "stores blocks + tags + hashes + secret key on its own disk");
    match save_storage(&fname, &data, &hf, &tf, k) {
        Ok(_) => {
            ok(&format!("csp_storage/{}/{}              (CSP archival copy)", fname, fname));
            ok(&format!("edge_storage/{}/blocks/block_NNNN.bin  ({} raw block files)", fname, n));
            ok(&format!("edge_storage/{}/tags.txt            (index, hash, tag)", fname));
            ok(&format!("edge_storage/{}/key.secret          (K, never sent anywhere)", fname));
            if let Ok(t) = std::fs::read_to_string(format!("edge_storage/{}/tags.txt", fname)) {
                for l in t.lines().take(detail + 1) {
                    let shown = if l.len() > 90 { format!("{}…", &l[..90]) } else { l.to_string() };
                    note(&format!("tags.txt │ {}", shown));
                }
            }
        }
        Err(e) => bad(&format!("could not write storage: {}", e)),
    }
    say("EDGE", "builds Groth16 proofs π1 for circuit C1 (witness: K and the blocks of each batch):");
    note(&format!("(1) Poseidon(K) == H_K   {}", if pos(&[k]) == hk { "✔" } else { "✘" }));
    for i in 0..n.min(detail) {
        let h_ok = pos(&edge_blocks[i]) == hf[i];
        let t_ok = alg_sig(k, &edge_blocks[i]) == tf[i];
        note(&format!("(2) Poseidon(m_{}) == hm_{}  {}      (3) AS_K(m_{}) == τ_{}  {}", i, i, if h_ok { "✔" } else { "✘" }, i, i, if t_ok { "✔" } else { "✘" }));
    }
    if n > detail {
        note(&format!("    … the same two constraints hold for the other {} blocks", n - detail));
    }
    // C1 is proven per batch of `batch` blocks; a short last batch is padded with all-zero blocks
    // (hash = Poseidon(0,0,0,0), tag = 0), exactly as the contract pads when it builds x1.
    let nb = (n + batch - 1) / batch;
    let zero_blk = vec![Fr::zero(); SECTORS];
    let inputs1: Vec<String> = (0..nb)
        .map(|t| {
            let x = batch_x1(hk, &hf, &tf, t, batch, chain.zero_hash);
            let (hf_b, tf_b) = (&x[1..1 + batch], &x[1 + batch..]);
            let m_b: Vec<String> = (t * batch..(t + 1) * batch)
                .map(|i| json_fr_arr(edge_blocks.get(i).unwrap_or(&zero_blk)))
                .collect();
            format!("{{\"HK\":\"{}\",\"HF\":{},\"TF\":{},\"K\":\"{}\",\"m\":[{}]}}", dec(&hk), json_fr_arr(hf_b), json_fr_arr(tf_b), dec(&k), m_b.join(","))
        })
        .collect();
    say("EDGE", &format!("{} block(s) → {} C1 batch proof(s) of {} blocks, {} proving job(s) at a time", n, nb, batch, jobs.min(nb).max(1)));
    let t_prove1 = Instant::now();
    let proofs1 = match prove_batches(&c1, &inputs1, jobs) {
        Ok(p) => p,
        Err(e) => { bad(&format!("prover failed: {}", e)); return; }
    };
    let prove1_secs = t_prove1.elapsed().as_secs_f32();
    ok(&format!("witnesses satisfy all constraints → {} proof(s) generated in {:.1}s", nb, prove1_secs));
    show_proof(&proofs1[0]);
    say("EDGE", "calls registerMetadata(ID_F, T_F, π1[])");
    say("CHAIN", "registerMetadata: Groth16 Verify(vk1, x1_t, π1_t) for every batch t …");
    let t_verify1 = Instant::now();
    chain.register_metadata(id_f, tf.clone(), &proofs1, "c1_reg").unwrap();
    let verify1_secs = t_verify1.elapsed().as_secs_f32();
    ok("all batch proofs valid → tags stored, EMIT FileTagsUpdated");
    say("CHAIN", "on-chain record for this file is now:");
    {
        let e = chain.files.get(&id_f).unwrap();
        note(&format!("ID_F     = {}", id_f));
        note(&format!("ID_edge  = {}", e.id_edge));
        note(&format!("H_K      = {}   (commitment only, K itself is NOT on chain)", hx(&e.hk)));
        note(&format!("H_F      = {}", hxs(&e.hf)));
        note(&format!("T_F      = {}", hxs(e.tags.as_ref().unwrap())));
        note("the file content itself is NOT on chain – only hashes and tags");
    }
    let mut bad_tf = tf.clone();
    bad_tf[0] += Fr::one();
    say("CSP", "(attack demo) malicious party submits a forged tag vector together with the honest proofs π1");
    match chain.register_metadata(id_f, bad_tf, &proofs1, "c1_forged") {
        Err(e) => bad(&format!("ABORT \"{}\"  – the proof does not match the forged public input", e)),
        Ok(_) => bad("forgery accepted?!"),
    }

    // ───────────── Phase 4: Corruption (optional) ─────────────
    if let Some(cb) = corrupt {
        banner("PHASE 4 · (demo) DATA LOSS ON EDGE DEVICE");
        if cb < n {
            let p = format!("edge_storage/{}/blocks/block_{:04}.bin", fname, cb);
            let mut bytes = std::fs::read(&p).unwrap();
            let before = esc(&bytes);
            bytes[0] ^= 0x01;
            std::fs::write(&p, &bytes).unwrap();
            say("EDGE", &format!("block file {} silently changes on disk (bit-rot / malicious edit)", p));
            note(&format!("before: \"{}\"", before));
            note(&format!("after : \"{}\"", esc(&bytes)));
            note("nobody has been told – the audit has to catch it");
        } else {
            note(&format!("block {} does not exist (n = {}), nothing corrupted", cb, n));
        }
    }

    // ───────────── Phase 5: Audits ─────────────
    banner(&format!("PHASE 5 · PERIODIC AUDITING  ({} rounds, {} of {} blocks challenged each)", rounds, c, n));
    let mut audit_prove_secs = 0f32;
    for r in 1..=rounds {
        println!("\n{}── audit round {} ──{}", BOLD, r, RST);
        say("EDGE", "SLA period reached → requests challenge seed (step 5)");
        let (chal, seed) = chain.request_seed();
        say("CHAIN", &format!("(step 6) issues Chal_id = {}, seed S = {}", chal, hx(&seed)));
        let idx = prf1(seed, c, n);
        let v = prf2(seed, c);
        say("EDGE", &format!("I = PRF1(S,c) = {:?}", idx));
        say("EDGE", &format!("V = PRF2(S,c) = {}", hxs(&v)));
        say("EDGE", &format!("reads the {} challenged blocks from its disk: edge_storage/{}/blocks/", c, fname));
        let disk_blocks = load_blocks(&fname, n);
        let magg = aggregate(&disk_blocks, &idx, &v);
        let tau_agg = agg_tag(&tf, &idx, &v);
        let h_magg = pos(&magg);
        say("EDGE", "aggregates challenged blocks and tags (eqn. 2):");
        explain_aggregation(&tf, &idx, &v, k, &magg, tau_agg, detail);
        say("EDGE", &format!("H_magg = Poseidon(m_agg) = {}", hx(&h_magg)));
        say("EDGE", "circuit C2 constraints evaluated:");
        note(&format!("(1) Poseidon(K) == H_K          {}", if pos(&[k]) == hk { "✔" } else { "✘" }));
        note(&format!("(2) Poseidon(m_agg) == H_magg    {}", if pos(&magg) == h_magg { "✔" } else { "✘" }));
        note(&format!("(3) AS_K(m_agg) == τ_agg         {}", if alg_sig(k, &magg) == tau_agg { "✔" } else { "✘" }));
        let input2 = format!("{{\"HK\":\"{}\",\"tauAgg\":\"{}\",\"Hmagg\":\"{}\",\"K\":\"{}\",\"magg\":{}}}", dec(&hk), dec(&tau_agg), dec(&h_magg), dec(&k), json_fr_arr(&magg));
        let tag = format!("c2_r{}", r);
        say("EDGE", "generates witness and Groth16 proof π2 for circuit C2 …");
        let t_p2 = Instant::now();
        let proof2 = match prove(&c2, &input2, &tag) {
            Ok(p) => {
                ok("witness satisfies all constraints → proof generated");
                show_proof(&p);
                p
            }
            Err(e) => {
                bad(&format!("the circuit rejects the witness: {}", e));
                bad("no valid proof can be produced for data that does not match the tags");
                say("EDGE", "submits a made-up proof anyway to avoid a timeout");
                let f = format!("{}/work/{}_forged_proof.json", BUILD, tag);
                std::fs::write(&f, FORGED_PROOF).ok();
                f
            }
        };
        audit_prove_secs += t_p2.elapsed().as_secs_f32();
        say("EDGE", "(step 7b) sends H_magg copy to CSP over TLS");
        say("CSP", &format!("stores H_magg = {} for Chal_id {} (guards against false attribution)", hx(&h_magg), chal));
        say("EDGE", "(step 7a) sends (ID_F, Chal_id, H_magg, π2) to PROXY");
        say("PROXY", "verifies device id of sender … ok");
        if r == 1 {
            say("CSP", "(attack demo) CSP colludes with edge and submits the PoP itself");
            match chain.verify_pop("CSP", id_f, chal, h_magg, &proof2, &tag, false) {
                Err(e) => { say("CHAIN", "VerifyPoP called by CSP …"); bad(&format!("ABORT \"{}\"  (only the proxy may submit)", e)); }
                Ok(_) => bad("accepted?!"),
            }
        }
        say("PROXY", "(step 8) submits (ID_F, Chal_id, H_magg, π2) from its wallet");
        say("CHAIN", "VerifyPoP …");
        let res = chain.verify_pop("PROXY", id_f, chal, h_magg, &proof2, &tag, true).unwrap();
        if res {
            ok("Verify(vk2, x2, π2) = 1   → AuditLog += PASS, EMIT AuditReportRecorded");
        } else {
            bad("Verify(vk2, x2, π2) = 0   → AuditLog += FAIL, EMIT AuditReportRecorded");
        }
    }

    // ───────────── Phase 6: SLA enforcement ─────────────
    banner("PHASE 6 · SLA ENFORCEMENT  (step 9)");
    say("CLIENT", "calls SLAEnforcementRequest()");
    let total = chain.audit_log.len();
    let passed = chain.audit_log.iter().filter(|e| e.2).count();
    let pctok = passed * 100 / total.max(1);
    say("CHAIN", "reads the audit log:");
    for (f, ch, r) in &chain.audit_log {
        note(&format!("file {}  challenge {}  →  {}", f, ch, if *r { "PASS" } else { "FAIL" }));
    }
    say("CHAIN", &format!("audit log: {} / {} passed = {}%", passed, total, pctok));
    if pctok >= 90 {
        *chain.balances.get_mut("CLIENT").unwrap() -= 50;
        *chain.balances.get_mut("CSP").unwrap() += 50;
        ok("SLA met → 50 tokens CLIENT → CSP");
    } else {
        *chain.balances.get_mut("CSP").unwrap() -= 100;
        *chain.balances.get_mut("CLIENT").unwrap() += 100;
        bad("SLA violated → penalty: 100 tokens CSP → CLIENT");
    }
    say("CHAIN", &format!("balances: CLIENT = {}, CSP = {}", chain.bal("CLIENT"), chain.bal("CSP")));

    // ───────────── timing summary ─────────────
    banner("TIMING SUMMARY");
    note(&format!("file                : {} bytes → {} blocks of {} bytes ({} sectors × {} bytes)", data.len(), n, block_bytes(), SECTORS, sector_bytes()));
    note(&format!("C1 (tag circuit)    : {} constraints per batch of {} blocks, {} batch proof(s)", c1.constraints, batch, nb));
    note(&format!("C2 (PoP circuit)    : {} constraints", c2.constraints));
    note(&format!("setup (compile+keys): {:.1}s   (cached after the first run for this --batch / --sector-bytes)", setup_secs));
    note(&format!("C1 prove            : {:.1}s wall clock, {} job(s) in parallel", prove1_secs, jobs.min(nb).max(1)));
    note(&format!("C1 verify (contract): {:.1}s for {} proof(s)", verify1_secs, nb));
    note(&format!("C2 prove            : {:.1}s total over {} audit round(s), {:.1}s each", audit_prove_secs, rounds, audit_prove_secs / rounds.max(1) as f32));
    note(&format!("whole run           : {:.1}s", t_total.elapsed().as_secs_f32()));
    println!();
}
