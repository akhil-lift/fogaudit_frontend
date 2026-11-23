pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";

// ─────────────────────────────────────────────────────────────────────────
// Algebraic signature (Chen et al.):   tau = AS_K(m) = sum_{j=1..S} b_j * K^j
// All arithmetic is in the BN254 scalar field, exactly like the Rust code.
//
// Evaluated with Horner's rule:
//     tau = K * (b_1 + K * (b_2 + K * ( ... + K * b_S)))
// This needs only S multiplications (one quadratic constraint each); the
// earlier "powers + terms" form needed 2S-1.  The value is identical.
// ─────────────────────────────────────────────────────────────────────────
template AlgSig(S) {
    signal input K;
    signal input m[S];
    signal output tau;

    signal h[S];                 // h[j] = b_{j+1} + K * h[j+1],  h[S-1] = b_S
    h[S-1] <== m[S-1];
    for (var j = S - 2; j >= 0; j--) {
        h[j] <== m[j] + K * h[j+1];
    }
    tau <== K * h[0];
}

// ─────────────────────────────────────────────────────────────────────────
// Circuit C1  –  tag verification  (metadata registration, Algorithm 2)
//
// C1 is instantiated for a BATCH of N blocks (N is a small fixed parameter,
// default 8), not for the whole file.  A file with many blocks is registered
// with ceil(n/N) proofs of the SAME circuit, so the circuit, its proving key
// and its powers-of-tau never depend on the file size.
//
//   public  : HK, HF[N], TF[N]
//   private : K, m[N][S]          (the secret key and the batch's blocks)
//
//   (1) HK    = Poseidon(K)
//   (2) HF[i] = Poseidon(m[i])         for every block i of the batch
//   (3) TF[i] = AS_K(m[i])             for every block i of the batch
// ─────────────────────────────────────────────────────────────────────────
template TagCircuit(N, S) {
    signal input HK;
    signal input HF[N];
    signal input TF[N];

    signal input K;
    signal input m[N][S];

    // (1) key commitment
    component hk = Poseidon(1);
    hk.inputs[0] <== K;
    hk.out === HK;

    component hb[N];
    component as_[N];
    for (var i = 0; i < N; i++) {
        // (2) block hash
        hb[i] = Poseidon(S);
        for (var j = 0; j < S; j++) {
            hb[i].inputs[j] <== m[i][j];
        }
        hb[i].out === HF[i];

        // (3) algebraic-signature tag
        as_[i] = AlgSig(S);
        as_[i].K <== K;
        for (var j = 0; j < S; j++) {
            as_[i].m[j] <== m[i][j];
        }
        as_[i].tau === TF[i];
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Circuit C2  –  proof of possession  (periodic audit, Algorithm 3)
//
//   public  : HK, tauAgg, Hmagg
//   private : K, magg[S]          (secret key and the aggregated block)
//
//   (1) HK     = Poseidon(K)
//   (2) Hmagg  = Poseidon(magg)
//   (3) tauAgg = AS_K(magg)
// ─────────────────────────────────────────────────────────────────────────
template PoPCircuit(S) {
    signal input HK;
    signal input tauAgg;
    signal input Hmagg;

    signal input K;
    signal input magg[S];

    component hk = Poseidon(1);
    hk.inputs[0] <== K;
    hk.out === HK;

    component hm = Poseidon(S);
    for (var j = 0; j < S; j++) {
        hm.inputs[j] <== magg[j];
    }
    hm.out === Hmagg;

    component as_ = AlgSig(S);
    as_.K <== K;
    for (var j = 0; j < S; j++) {
        as_.m[j] <== magg[j];
    }
    as_.tau === tauAgg;
}
