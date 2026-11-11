# iraca-2

Adversarial and differential verification harness for ML-DSA (FIPS 204),
the NIST post-quantum lattice signature standard. MIT OR Apache-2.0.  
FIPS 204 · ML-DSA · differential oracle · malleability · hint canonicity

**English** · [Español](#español)

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it
is not distributed through crates.io or any public registry.

This is not abandonment, not an incident, and there was no breach. It is a
decision, and it is worth saying what it rests on. Through 2026 the package
registries and code-hosting platforms were hit by sustained, chained
supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious
extensions that exfiltrated thousands of private repositories. For a
cryptographic verification tool, hosting the source there stopped being a
neutral decision.

**The licence has not changed and the code is still available to anyone who
asks** — delivered with a signature and a checksum, at no cost, with no NDA, no
restriction on what you publish about it, and no expiry.

### Get the source

Request the signed source via **[xiliux.com](https://xiliux.com)**.

---

## What it does

The ecosystem covers **conformance** (FIPS 204 KAT vectors test valid inputs).
What nobody owns is the **adversarial layer**: what does `verify` do with
something that is _not_ a valid signature — a mutated signature, a non-canonical
encoding, wrong lengths, crossed messages or keys? A correct `verify` rejects
them all; one that accepts any of them is malleability or worse.

Iraca-2 attacks ML-DSA in three phases, all measured:

### Phase 1 — single-implementation abuse (`ml-dsa` 0.1.1, RustCrypto)

| Campaign | Variants tested | Incorrectly accepted |
|---|---|---|
| Malleability (exhaustive 1-bit sweep over a valid signature) | 37,016 | **0** |
| Structural abuse (zeros, ones, length, crossed message, crossed key) | 7 | **0** |

Verdict: **SECO (dry)**. The bit-flip abuse surface is well-closed in this mature
implementation. The probable finding lives in the differential (phase 2) and in
the deep structural canonicity of the encoding.

### Phase 2 — differential `ml-dsa` ↔ `fips204`

Two fully independent implementations of FIPS 204 (`ml-dsa` by RustCrypto;
`fips204` by integritychain), byte-compatible wire format (public key 2592 B,
signature 4627 B). The same bytes are fed to both verifiers without translation.

| Control / Campaign | Result |
|---|---|
| Cross A→B (ml-dsa signs → fips204 verifies) | ✅ PASS |
| Cross B→A (fips204 signs → ml-dsa verifies) | ✅ PASS |
| Shared corpus (valid sig + 1-bit sweep + structural + crossed): **37,024 entries** | **0 disagreements** |

The two positive-control crosses make the "0 disagreements" credible: the
implementations agree in what they accept _and_ in what they reject.

### Phase 3 — deep hint canonicity

FIPS 204 (Algorithm 21, `HintBitUnpack`) imposes explicit canonicity rules on
the hint `h`: non-decreasing cumulative counts, counts `≤ ω`, strictly
increasing indices per segment, and all-zero padding. A signature whose `h`
violates a rule but still verifies is a second encoding of the same object —
genuine malleability.

7 structural variants tested (swapped indices, duplicate index, non-zero
padding `0x03` / `0xFF`, cumulative count exceeding ω, decreasing count, `z`
out-of-range). **0 accepted by either implementation; 0 disagreements.**

Verdict (all three phases): **SECO**. Both mature ML-DSA implementations are
robust to structural non-canonicity, and they agree on every entry.

---

## Español

**[English](#iraca-2)** · Español

Arnés de verificación adversarial y diferencial para ML-DSA (FIPS 204),
la firma lattice post-cuántica del NIST. MIT OR Apache-2.0.  
FIPS 204 · ML-DSA · oráculo diferencial · maleabilidad · canonicidad del hint

---

### El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni
se distribuye por crates.io ni ningún registro público.

No es abandono ni un incidente: es una decisión. A lo largo de 2026 los
registros de paquetes y las plataformas de código han sufrido ataques
encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto,
extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar
aquí el código de una herramienta de verificación criptográfica dejó de ser una
decisión neutra.

**La licencia no cambia y el código se sigue entregando a quien lo pida**, con
su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo
que publique y sin caducidad.

### Conseguir el código

Solicite el fuente firmado en **[xiliux.com](https://xiliux.com)**.

---

### Qué hace

El ecosistema cubre la **conformidad** (vectores KAT de FIPS 204 sobre entradas
válidas). Lo que nadie tiene como dueño es la capa **adversarial**: qué hace
`verify` con lo que NO es una firma válida. Un `verify` correcto lo rechaza
todo; uno que acepta algo es maleabilidad o algo peor.

Iraca-2 ataca ML-DSA en tres fases, todas medidas:

### Fase 1 — abuso de una implementación (`ml-dsa` 0.1.1, RustCrypto)

| Campaña | Variantes probadas | Aceptadas indebidamente |
|---|---|---|
| Malleability (barrido exhaustivo de 1 bit sobre una firma válida) | 37 016 | **0** |
| Abuso estructural (ceros, unos, longitud, mensaje cruzado, clave cruzada) | 7 | **0** |

**Veredicto: SECO.** La superficie de abuso por bit-flip está bien cerrada.

### Fase 2 — diferencial `ml-dsa` ↔ `fips204`

Dos implementaciones completamente independientes de FIPS 204, con formato de
wire byte-compatible.

| Control / Campaña | Resultado |
|---|---|
| Cruce A→B (ml-dsa firma → fips204 verifica) | ✅ VERDE |
| Cruce B→A (fips204 firma → ml-dsa verifica) | ✅ VERDE |
| Corpus compartido (firma válida + barrido + estructurales + cruzados): **37 024 entradas** | **0 desacuerdos** |

### Fase 3 — canonicidad profunda del hint

7 variantes estructurales del hint `h` (índices intercambiados, índice duplicado,
relleno no nulo, cuenta acumulada `> ω`, cuenta decreciente, `z` fuera de rango).
**0 aceptadas por ninguna implementación; 0 desacuerdos.**

**Veredicto (tres fases): SECO.** Las dos implementaciones maduras de ML-DSA son
robustas al abuso estructural y coinciden en cada entrada del corpus.

---

*iraca-2* — © 2026 Juan Carlos Isaza. Licence: **MIT OR Apache-2.0**.  
La licencia no cambia: lo que cambia es cómo se entrega el código.
