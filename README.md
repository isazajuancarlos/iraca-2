<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- Titularidad: Isaza Arenas. Xiliux no es persona jurídica. -->

# Iraca-2

**Verificación adversarial y diferencial de ML-DSA (FIPS 204), la firma lattice
post-cuántica del NIST.**

Hermano de [Iraca](../iraca) (que hace lo mismo con las firmas hash-based de la
Lean roadmap de Ethereum). La tesis es la misma: el ecosistema ya cubre la
**conformidad** (vectores KAT, entradas válidas) y la **interop**; nadie tiene
como dueño la capa **adversarial** —qué hace `verify` ante lo que NO es una firma
válida: firmas mutadas, codificaciones no canónicas, longitudes mal, mensajes o
claves cruzados—. Un `verify` correcto las rechaza todas; una que acepte alguna
es maleabilidad o algo peor.

## Qué mira, y por qué es el hueco

- **Conformidad** (cubierto por otros): los KAT de FIPS 204, que prueban entradas
  válidas.
- **Iraca-2** (el hueco): abuso y desacuerdo, en tres fases (las tres hechas y
  medidas). Fase 1 — abuso de una sola implementación (`ml-dsa` de RustCrypto).
  Fase 2 — **diferencial** entre `ml-dsa` y `fips204` (dos implementaciones
  independientes del mismo estándar), cazando entradas que una acepta y la otra
  rechaza. Fase 3 — **canonicidad profunda**: mutaciones estructurales del hint que
  el barrido de bits no alcanza.

El foso: Xiliux ya opera **quipu**, una implementación conformante independiente,
así que montar el diferencial cuesta lo que a nadie más.

## Fase 1 — medición (hecha)

`cargo run --release --example medir`

Objetivo: `ml-dsa` 0.1.1 (RustCrypto, ML-DSA-87), por su API pública sin modificar.

| campaña | variantes | aceptadas indebidamente |
|---|---|---|
| malleability (barrido exhaustivo de 1 bit sobre una firma válida) | 37 016 | **0** |
| abuso estructural (ceros, unos, longitud, mensaje cruzado, clave cruzada) | 7 | **0** |

**Veredicto: SECO** — `verify` rechaza toda variante no canónica, mutada o ajena.
Es un resultado honesto y esperado de una implementación madura: la capa de abuso
de bit-flip está bien cerrada. El hallazgo probable NO vive aquí, vive en el
**diferencial** (fase 2) y en la canonicidad profunda de la codificación (rangos
de `z`, peso del *hint* `h`), que exigen construir codificaciones válidas-pero-no-
canónicas, no solo invertir bits.

Control positivo (D33): la prueba `la_firma_valida_verifica` garantiza que el
arnés no dice «0 aceptadas» por rechazarlo todo.

## Fase 2 — diferencial `ml-dsa` ↔ `fips204` (hecha)

`cargo run --release --example medir` (imprime fase 1 y fase 2).

Segunda implementación: `fips204` 0.4.6 (integritychain), código totalmente
distinto de `ml-dsa` (otro NTT, otro muestreo, otra codificación). Las dos
codificaciones son byte-compatibles por FIPS 204 (clave pública 2592 B, firma
4627 B), así que los mismos bytes se dan a las dos puertas sin traducir; contexto
vacío en ambas (variante «pura»).

| control / campaña | resultado |
|---|---|
| cruce A→B (ml-dsa firma → fips204 verifica) | **VERDE** |
| cruce B→A (fips204 firma → ml-dsa verifica) | **VERDE** |
| corpus compartido (firma válida + barrido exhaustivo de 1 bit + estructurales + mensaje/clave cruzados): 37 024 entradas | **0 desacuerdos** accept/reject |

**Veredicto: SECO** — las dos implementaciones conformes ACUERDAN en cada entrada
del corpus. Los dos cruces de control en verde (D30) hacen creíble el «0
desacuerdos»: no es que las implementaciones no se entiendan, es que coinciden
también en lo que rechazan. El módulo `diferencial` es el arnés reutilizable
(`verificar_fips`, `verificar_mldsa_desde_pk`, `campana_diferencial`).

## Fase 3 — canonicidad profunda (hecha)

`cargo run --release --example medir` (imprime las tres fases).

El barrido de 1 bit de las fases 1 y 2 no puede construir codificaciones
**válidas-pero-no-canónicas**: hay que decodificar la firma en sus tres partes
(c̃ ‖ z ‖ h) y perturbar la ESTRUCTURA con cambios **multi-byte**. El módulo
`canonicidad` ataca el *hint* `h`, cuya codificación es byte-alineada y a la que
FIPS 204 (Algoritmo 21, `HintBitUnpack`) impone reglas de canonicidad explícitas:
cuentas acumuladas no decrecientes y `≤ ω`, índices **estrictamente crecientes**
por segmento, y relleno **todo ceros**. Una firma cuyo `h` viola una regla pero
que aun así verifica es una segunda codificación del mismo objeto: maleabilidad.

Sobre la firma base (elegida por búsqueda hasta hallar un hint con un segmento de
≥ 2 índices — control D30, sin él no hay qué reordenar) se prueban 7 variantes:

| variante no canónica | por qué es no canónica | resultado |
|---|---|---|
| dos índices intercambiados | orden no creciente; mismo conjunto de índices (maleabilidad genuina, verificada: multiset idéntico) | rechazada por ambas |
| índice duplicado | no estrictamente creciente | rechazada por ambas |
| relleno no nulo `0x03` / `0xFF` | FIPS 204 exige relleno cero; valores multi-bit que un flip de 1 bit no alcanza | rechazada por ambas |
| cuenta acumulada final `> ω` | `y[ω+i] > ω` | rechazada por ambas |
| cuenta acumulada decreciente | `y[ω+i] < Index` | rechazada por ambas |
| `z` fuera de rango (`w=0 ⇒ z=γ₁`) | `‖z‖∞ ≥ γ₁ − β`, cazado por el chequeo de norma | rechazada por ambas |

**Veredicto: SECO** — **0 aceptadas por ninguna** de las dos implementaciones y
**0 desacuerdos**; los dos controles positivos (firma base verifica en ml-dsa y en
fips204) en verde, y estructura de hint suficiente confirmada (D30). El detector de
aceptación y el de desacuerdo se prueban con parejas que fabrican una aceptación /
un rechazo cruzado (D33), para que el «0» no sea el de un arnés ciego.

**Sobre `z`**: su codificación `BitPack(z, γ₁−1, γ₁)` es una biyección sobre el
rango válido (20 bits por coeficiente, sin espacio para dos representantes de un
mismo valor mod q), así que no hay «representante equivalente»: el único abuso es
un coeficiente fuera de rango, y lo caza la norma de `verify`. La hipótesis de la
fase 2 —«el hallazgo probable vive en la estructura, no en el bit»— queda
**refutada** para estas dos implementaciones: las dos son robustas también a la
no-canonicidad estructural.

## Licencia

MIT OR Apache-2.0. No depende de quipu (AGPL); consume `ml-dsa` (Apache/MIT).
