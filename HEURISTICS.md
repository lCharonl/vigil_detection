# Heuristics

Active detection rules. To add one, see [ADDING_HEURISTICS.md](ADDING_HEURISTICS.md).

## Model

For a domain `d`, the score is the sum of the points of every rule `r`:

```
S(d) = Σ_r s_r(d)          alert(d) ⇔ S(d) ≥ τ          (τ = 50, --threshold)
```

A whitelisted domain (`whitelist.yaml`) gets `S = 0` before any rule runs.

| Rule | `s_r` | Data |
|---|---|---|
| `check_typosquatting` | 60, or 30 if technique = `tld_swap` | `brands_typosquats.yaml` |
| `check_brand_in_subdomain` | 40 | `brands_legits_domain.yaml` |
| `check_keywords` | min(40, Σ w(k)) | `phishing_keywords.yaml` |

Maximum contribution of each rule against the threshold:

```
 0         10        20        30        40   τ=50      60
 ├─────────┴─────────┴─────────┴─────────┴────┼─────────┤
 keywords  ██████████████████████████████████░  (max 40)
 brand_sub ██████████████████████████████████░  (40)
 tld_swap  ███████████████████████████          (30)
 typosquat ████████████████████████████████████████████ (60)  ← alone ≥ τ
```

Domain decomposition and the zone each rule reads:

```
   paypal . login . example-secure . xyz
   └─────sub────┘   └───root────┘   └suffix┘
   brand_in_subdomain ──┘
   keywords ────────────┴──────────┘
   typosquatting: every label suffix  fqdn, login.example…, example…, xyz
```

All rules skip official domains (`D_legit`), as `fqdn` or any parent of `fqdn`.

## `check_typosquatting`

Let `V = ⋃_b ⋃_t T_t(root_b).suffix_b` be the precomputed set of variants of every official domain `b`, over the generation techniques `T_t` (`scripts/generate_typosquats.py`):

`omission`, `repetition`, `transposition`, `replacement`, `insertion`, `homoglyph`, `hyphenation`, `vowel_swap`, `bitsquatting`, `prefix_token`, `dot_insertion`, `tld_swap`.

With `ℓ = (ℓ₁ … ℓₙ)` the labels of `d`:

```
match(d) ⇔ ∃ i < n−1 : ℓᵢ.….ℓₙ ∈ V
```

Lookup is a hash probe per label suffix: `O(n)`, no edit-distance computation at runtime.

## `check_brand_in_subdomain`

Let `K` be the normalized brand keys (lowercase, `[a-z0-9]` only), `J(x)` the string `x` without `.-_`, and `Tok(x)` its tokens split on `.-_`.

```
match(d) ⇔ ∃ k ∈ K :  ( |k| ≥ 5  ∧  k ⊂ J(sub) )          substring
                    ∨ ( 2 ≤ |k| < 5  ∧  k ∈ Tok(sub) )      whole token
```

Short keys require a whole token to bound false positives (`ing` must not match `building`). The longest match gives the brand named in the reason.

## `check_keywords`

Let `W` be the keywords (`w = 10`) and patterns (`w = 20`) of `phishing_keywords.yaml`, normalized as above. Text `x = sub.root` (suffix excluded). Matched set:

```
M = { k ∈ W : |k| ≥ 5 ∧ k ⊂ J(x) }  ∪  { k ∈ W : |k| < 5 ∧ k ∈ Tok(x) }
s = min( 40,  Σ_{k∈M} w(k) )
```

- Long keys use one alternation regex sorted by decreasing length. Matches are leftmost, non-overlapping, longest first: `securelogin` counts once (pattern, 20), not `secure` + `login`.
- Cap 40 < τ: keywords never alert alone, they only tip a domain over τ with a brand rule.

## Worked examples

| Domain | Terms | S | Alert |
|---|---|---|---|
| `paypa1.com` | typosquat 60 | 60 | yes |
| `paypal.login.example.xyz` | brand_sub 40 + keyword 10 | 50 | yes |
| `secure-login.example.xyz` | pattern 20 | 20 | no |
| `mon-espace-client-suivi-colis.xyz` | 20 + 10 + 10 | 40 | no |

## Planned

Risky TLDs, certificate authority, subdomain depth (`rules_context.py`).
