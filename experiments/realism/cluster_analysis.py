"""
Embedding-based realism analysis: VeriVul / FormAI (synthetic) vs
ICVul / TitanVul / mono / ARVO (real).

Distance metric: per-dimension two-sample Kolmogorov-Smirnov test averaged
across embedding dimensions, plus Centroid distance as a cheap sanity check.
Cluster evaluation: ARI, V-Measure, Silhouette under K-Means (k=6).
Projections: PCA + t-SNE.

Usage:
    python cluster_analysis.py --suffix pplx06b
    python cluster_analysis.py --suffix jinav2code

Outputs:
  data/realism_samples/cluster_metrics_<suffix>.json
  figures/cluster_pca_<suffix>.pdf
  figures/cluster_tsne_<suffix>.pdf
"""
import argparse
import os
import json
import sys
import numpy as np
from pathlib import Path
from scipy.stats import ks_2samp
from sklearn.cluster import KMeans
from sklearn.metrics import (adjusted_rand_score,
                             v_measure_score,
                             silhouette_score)
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT     = Path(__file__).parent
SAMPLES  = Path(os.environ.get("REALISM_DIR", ROOT / "data" / "realism_samples"))
FIGS     = ROOT / "figures"
FIGS.mkdir(parents=True, exist_ok=True)

DATASETS  = ["verivul", "icvul", "titanvul", "mono", "arvo", "formai"]
REAL      = ["icvul", "titanvul", "mono", "arvo"]
SYNTH     = ["verivul", "formai"]
COLORS    = {"verivul":  "#7e3ff2",
             "icvul":    "#0a84ff",
             "titanvul": "#34c759",
             "mono":     "#ff9f0a",
             "arvo":     "#5ac8fa",
             "formai":   "#ff3b30"}
LABELS    = {"verivul":  "VeriVul",
             "icvul":    "ICVul",
             "titanvul": "TitanVul",
             "mono":     "mono",
             "arvo":     "ARVO",
             "formai":   "FormAI"}


def load(suffix, name):
    tag  = f"_{suffix}" if suffix else ""
    path = SAMPLES / f"emb{tag}_{name}.npy"
    return np.load(path)


def l2_normalize(x):
    n = np.linalg.norm(x, axis=1, keepdims=True) + 1e-12
    return x / n


def centroid_dist(X, Y):
    return float(np.linalg.norm(X.mean(0) - Y.mean(0)))


def per_dim_ks(X, Y, alpha=0.05, sample=4000, seed=42):
    """Average per-dimension KS statistic between X and Y, plus the
    fraction of dimensions where p<alpha (statistically significant)."""
    rng = np.random.default_rng(seed)
    if X.shape[0] > sample:
        X = X[rng.choice(X.shape[0], sample, replace=False)]
    if Y.shape[0] > sample:
        Y = Y[rng.choice(Y.shape[0], sample, replace=False)]
    D = X.shape[1]
    stats  = np.empty(D, dtype=np.float32)
    pvals  = np.empty(D, dtype=np.float32)
    for d in range(D):
        s, p = ks_2samp(X[:, d], Y[:, d])
        stats[d] = s
        pvals[d] = p
    return {
        "ks_mean":   float(stats.mean()),
        "ks_median": float(np.median(stats)),
        "ks_max":    float(stats.max()),
        "frac_sig":  float((pvals < alpha).mean()),
    }


def _median_heuristic_sigma(Z, sample=2000, seed=42):
    """Pick the RBF bandwidth as the median pairwise distance (Gretton et al.)."""
    rng = np.random.default_rng(seed)
    if Z.shape[0] > sample:
        Z = Z[rng.choice(Z.shape[0], sample, replace=False)]
    sq = (Z * Z).sum(1, keepdims=True)
    d2 = sq + sq.T - 2 * (Z @ Z.T)
    np.maximum(d2, 0, out=d2)
    iu = np.triu_indices(d2.shape[0], k=1)
    med = float(np.median(d2[iu]))
    return float(np.sqrt(med / 2.0)) if med > 0 else 1.0


def mmd_rbf(X, Y, sigma=None, sample=4000, seed=42):
    """Unbiased MMD^2 with an RBF kernel.

    Uses the median heuristic on the joint sample for sigma if not supplied.
    """
    rng = np.random.default_rng(seed)
    if X.shape[0] > sample:
        X = X[rng.choice(X.shape[0], sample, replace=False)]
    if Y.shape[0] > sample:
        Y = Y[rng.choice(Y.shape[0], sample, replace=False)]

    if sigma is None:
        sigma = _median_heuristic_sigma(np.vstack([X, Y]), sample=sample, seed=seed)
    gamma = 1.0 / (2.0 * sigma * sigma)

    def _k(A, B):
        a = (A * A).sum(1, keepdims=True)
        b = (B * B).sum(1, keepdims=True).T
        d = a + b - 2 * (A @ B.T)
        np.maximum(d, 0, out=d)
        return np.exp(-gamma * d)

    Kxx = _k(X, X); Kyy = _k(Y, Y); Kxy = _k(X, Y)
    n, m = X.shape[0], Y.shape[0]
    np.fill_diagonal(Kxx, 0); np.fill_diagonal(Kyy, 0)
    mmd2 = (Kxx.sum() / (n * (n - 1))
            + Kyy.sum() / (m * (m - 1))
            - 2 * Kxy.mean())
    return {
        "mmd2":  float(mmd2),
        "mmd":   float(np.sqrt(max(mmd2, 0))),
        "sigma": float(sigma),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suffix", default="",
                    help="filename tag of the embedding files "
                         "(e.g. 'pplx06b' → emb_pplx06b_<dataset>.npy). "
                         "Empty = jina-v5 default.")
    ap.add_argument("--label",  default=None,
                    help="display label for plot titles "
                         "(default: derived from suffix)")
    ap.add_argument("--no-title", action="store_true", help="omit figure titles")
    ap.add_argument("--no-tsne", action="store_true",
                    help="skip t-SNE projection (slow)")
    args = ap.parse_args()

    suffix = args.suffix
    label  = args.label or (suffix if suffix else "jina-v5")
    tag    = f"_{suffix}" if suffix else ""

    embs = {}
    for ds in DATASETS:
        embs[ds] = l2_normalize(load(suffix, ds))
        print(f"{ds}: {embs[ds].shape}")

    out = {"pairwise": {}, "clustering": {}, "config": {
        "suffix": suffix,
        "label":  label,
        "dim":    int(embs["verivul"].shape[1]),
    }}

    # ── pairwise distances ───────────────────────────────────────────────────
    for real in REAL:
        out["pairwise"][real] = {}
        for synth in SYNTH:
            ks = per_dim_ks(embs[synth], embs[real])
            cd = centroid_dist(embs[synth], embs[real])
            mm = mmd_rbf(embs[synth], embs[real])
            out["pairwise"][real][synth] = {**ks, "centroid": cd, **mm}
            print(f"  {synth} vs {real}: ks_mean={ks['ks_mean']:.4f}  "
                  f"centroid={cd:.4f}  mmd={mm['mmd']:.4f}  "
                  f"frac_sig={ks['frac_sig']:.3f}",
                  flush=True)

    # ── clustering ───────────────────────────────────────────────────────────
    X = np.vstack([embs[d] for d in DATASETS])
    y_true = np.concatenate([np.full(embs[d].shape[0], i) for i, d in enumerate(DATASETS)])

    k = len(DATASETS)
    print(f"K-Means (k={k})...", flush=True)
    km = KMeans(n_clusters=k, random_state=42, n_init=10).fit(X)
    y_pred = km.labels_

    rng = np.random.default_rng(42)
    idx = rng.choice(X.shape[0], 5000, replace=False)
    sil = silhouette_score(X[idx], y_true[idx], metric="euclidean")

    out["clustering"] = {
        "ari":        float(adjusted_rand_score(y_true, y_pred)),
        "v_measure":  float(v_measure_score(y_true, y_pred)),
        "silhouette": float(sil),
        "k":          k,
        "n_total":    int(X.shape[0]),
    }
    print(f"  ARI={out['clustering']['ari']:.3f}  "
          f"V-Measure={out['clustering']['v_measure']:.3f}  "
          f"Silhouette={out['clustering']['silhouette']:.3f}", flush=True)

    out_path = SAMPLES / f"cluster_metrics{tag}.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Saved → {out_path}")

    # ── projections ──────────────────────────────────────────────────────────
    print("PCA...", flush=True)
    Xp = PCA(n_components=2, random_state=42).fit_transform(X)

    if not args.no_tsne:
        print("t-SNE (subsample 8000)...", flush=True)
        sub = rng.choice(X.shape[0], min(8000, X.shape[0]), replace=False)
        Xt = TSNE(n_components=2, random_state=42, perplexity=50,
                  init="pca", learning_rate="auto").fit_transform(X[sub])
        yt = y_true[sub]

    def plot(coords, labels, title, path):
        fig, ax = plt.subplots(figsize=(5, 4.2))
        for i, ds in enumerate(DATASETS):
            mask = labels == i
            ax.scatter(coords[mask, 0], coords[mask, 1],
                       s=3, alpha=0.45, c=COLORS[ds], label=LABELS[ds])
        if not args.no_title:
            ax.set_title(title, fontsize=11)
        ax.set_xticks([]); ax.set_yticks([])
        for spine in ax.spines.values(): spine.set_visible(False)
        leg = ax.legend(loc="upper right" if args.no_title else "best", fontsize=8, frameon=False, markerscale=2)
        for h in leg.legend_handles: h.set_alpha(1.0)
        fig.tight_layout()
        fig.savefig(path, dpi=200, bbox_inches="tight")
        plt.close(fig)
        print(f"  → {path}")

    plot(Xp, y_true, f"PCA of {label} embeddings",
         FIGS / f"cluster_pca{tag}.pdf")
    if not args.no_tsne:
        plot(Xt, yt, f"t-SNE of {label} embeddings",
             FIGS / f"cluster_tsne{tag}.pdf")

    print("Done.")


if __name__ == "__main__":
    main()
