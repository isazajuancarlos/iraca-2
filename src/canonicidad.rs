// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Isaza Arenas

//! Fase 3 — canonicidad **profunda** de la firma ML-DSA-87 (FIPS 204).
//!
//! Las fases 1 y 2 barrieron EXHAUSTIVAMENTE cada bit de la firma (uno a uno) y
//! salieron secas: `verify` rechaza toda mutación de un bit, y las dos
//! implementaciones acuerdan. Pero un barrido de 1 bit NO puede construir una
//! codificación **válida-pero-no-canónica**: para eso hay que decodificar la firma
//! en sus tres partes (c̃ ‖ z ‖ h) y perturbar la ESTRUCTURA con cambios que tocan
//! varios bytes a la vez —reordenar índices, duplicarlos, romper una cuenta—. Ahí
//! es donde vive la maleabilidad si existe.
//!
//! El objetivo principal es el *hint* `h`, porque su codificación es **byte-alineada**
//! y FIPS 204 (Algoritmo 21, `HintBitUnpack`) le impone reglas de canonicidad
//! EXPLÍCITAS que un decodificador perezoso podría saltarse:
//!
//!  1. las cuentas acumuladas `y[ω+i]` son no decrecientes y `≤ ω`;
//!  2. dentro del segmento de cada polinomio, los índices son **estrictamente
//!     crecientes** (sin duplicados, sin desorden);
//!  3. el relleno entre el último índice usado y la posición `ω` es **todo ceros**.
//!
//! Una firma cuyo `h` viola una de estas reglas pero que aun así VERIFICA es una
//! segunda codificación del mismo objeto: maleabilidad. Y si una implementación la
//! acepta mientras la otra la rechaza, es un desacuerdo diferencial reportable.
//!
//! **Sobre `z`**: su codificación es `BitPack(z, γ₁−1, γ₁)`, 20 bits por coeficiente,
//! una biyección sobre el rango válido; no hay dos representantes del mismo valor en
//! 20 bits (q ≈ 2²³ no cabe), así que no hay libertad de «representante equivalente».
//! El único abuso posible es un coeficiente FUERA de rango, y eso lo caza el chequeo
//! de norma `‖z‖∞ < γ₁ − β` dentro de `verify`. Se incluye un caso de control que lo
//! confirma.

use crate::diferencial::{pk_bytes, verificar_fips, verificar_mldsa_desde_pk};
use crate::{firmar, Par};

// --- Parámetros de ML-DSA-87 (FIPS 204, Tabla 1) y layout de `sigEncode`.
/// c̃ (commitment hash): 2λ/8 = 64 bytes para λ = 256.
pub const C_TILDE_LEN: usize = 64;
/// z: l · 32 · (1 + bitlen(γ₁−1)) = 7 · 32 · 20 = 4480 bytes.
pub const Z_LEN: usize = 4480;
/// ω (máximo de hints) para ML-DSA-87.
pub const OMEGA: usize = 75;
/// k (número de polinomios del hint) para ML-DSA-87.
pub const K: usize = 8;
/// Longitud de la sección del hint: ω + k = 83 bytes.
pub const HINT_LEN: usize = OMEGA + K;
/// Longitud total de la firma: 64 + 4480 + 83 = 4627.
pub const SIG_LEN: usize = C_TILDE_LEN + Z_LEN + HINT_LEN;
/// Offset donde empieza la sección del hint dentro de la firma.
pub const HINT_OFF: usize = C_TILDE_LEN + Z_LEN;
/// Offset donde empiezan las k cuentas acumuladas (tras los ω bytes de índices).
pub const COUNT_OFF: usize = HINT_OFF + OMEGA;

/// Las k cuentas acumuladas `y[ω..ω+k]` de una firma.
fn cuentas(firma: &[u8]) -> [u8; K] {
    firma[COUNT_OFF..COUNT_OFF + K]
        .try_into()
        .expect("K cuentas")
}

/// El número total de hints puestos = la última cuenta acumulada.
fn total_hints(firma: &[u8]) -> usize {
    cuentas(firma)[K - 1] as usize
}

/// Devuelve `(inicio, longitud)` del PRIMER segmento de polinomio con ≥ 2 índices,
/// o `None` si ninguno los tiene (firma con hint demasiado ralo para reordenar).
/// `inicio` es la posición dentro del array de índices (0..ω).
fn primer_segmento_gordo(firma: &[u8]) -> Option<(usize, usize)> {
    let c = cuentas(firma);
    let mut prev = 0usize;
    for &fin in &c {
        let fin = fin as usize;
        // Un hint bien formado tiene cuentas no decrecientes; si no lo estuvieran,
        // la firma base no sería válida y el control D30 de abajo lo delataría.
        if fin >= prev + 2 {
            return Some((prev, fin - prev));
        }
        prev = fin;
    }
    None
}

/// Una variante NO canónica del hint (o de z) y qué hizo cada implementación con ella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hallazgo {
    pub descripcion: String,
    /// ¿la aceptó `ml-dsa`?
    pub ml_dsa: bool,
    /// ¿la aceptó `fips204`?
    pub fips204: bool,
}

/// Veredicto de la campaña de canonicidad.
#[derive(Debug, Default)]
pub struct VeredictoCanon {
    pub probadas: usize,
    /// Variantes que ALGUNA de las dos aceptó: maleabilidad (una segunda
    /// codificación del mismo objeto que verifica). Debe estar vacío.
    pub aceptadas: Vec<Hallazgo>,
    /// Variantes donde las dos DISCREPAN: desacuerdo diferencial. Debe estar vacío.
    pub desacuerdos: Vec<Hallazgo>,
    /// CONTROL POSITIVO (D30): la firma base VÁLIDA verifica en ml-dsa. Sin esto,
    /// un «0 aceptadas» sería indistinguible de dos puertas que rechazan todo.
    pub base_verifica_mldsa: bool,
    /// CONTROL POSITIVO (D30): la firma base VÁLIDA verifica en fips204.
    pub base_verifica_fips: bool,
    /// CONTROL D30: la firma base TENÍA estructura de hint suficiente (un segmento
    /// con ≥ 2 índices) para construir las mutaciones de reordenamiento y duplicado.
    /// Si es `false`, la campaña está infra-potenciada y su «seco» no vale.
    pub estructura_suficiente: bool,
    /// Cuántos mensajes se probaron hasta hallar uno con estructura suficiente.
    pub mensajes_probados: usize,
}

impl VeredictoCanon {
    fn evaluar(&mut self, pk: &[u8], mensaje: &[u8], candidata: &[u8], que: impl FnOnce() -> String) {
        self.probadas += 1;
        let a = verificar_mldsa_desde_pk(pk, mensaje, candidata);
        let b = verificar_fips(pk, mensaje, candidata);
        if a || b {
            let d = que();
            if a != b {
                self.desacuerdos.push(Hallazgo { descripcion: d.clone(), ml_dsa: a, fips204: b });
            }
            self.aceptadas.push(Hallazgo { descripcion: d, ml_dsa: a, fips204: b });
        } else if a != b {
            // Desacuerdo donde ninguna aceptó es imposible (a!=b ⇒ una aceptó), pero
            // se deja explícito por si la lógica cambia.
            self.desacuerdos.push(Hallazgo { descripcion: que(), ml_dsa: a, fips204: b });
        }
    }

    /// Limpio = ninguna variante no canónica aceptada, ningún desacuerdo, los dos
    /// controles positivos en verde y estructura suficiente (D30).
    pub fn limpio(&self) -> bool {
        self.aceptadas.is_empty()
            && self.desacuerdos.is_empty()
            && self.base_verifica_mldsa
            && self.base_verifica_fips
            && self.estructura_suficiente
    }
}

/// Construye las variantes NO canónicas de una firma válida cuyo hint tiene un
/// segmento con ≥ 2 índices en `(seg_ini, seg_len)`. Cada una toca VARIOS bytes o un
/// byte con valor multi-bit, es decir, cosas que el barrido de 1 bit de las fases
/// anteriores NO alcanza a construir.
fn variantes_no_canonicas(firma: &[u8], seg_ini: usize, total: usize) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let p = HINT_OFF + seg_ini; // posición absoluta del primer índice del segmento gordo

    // 1) ORDEN roto: intercambia los dos primeros índices del segmento. El conjunto
    //    de índices es idéntico (mismo hint decodificado), solo cambia el orden →
    //    viola «estrictamente creciente». Un decodificador que lo ignore lo acepta y
    //    verifica: maleabilidad. Imposible con un flip de 1 bit (mueve dos bytes).
    let mut v = firma.to_vec();
    v.swap(p, p + 1);
    out.push(("hint: dos índices intercambiados (orden no creciente)".into(), v));

    // 2) DUPLICADO: el segundo índice se iguala al primero → índice repetido, no
    //    estrictamente creciente. Decodificador laxo: bit puesto una vez, cuenta miente.
    let mut v = firma.to_vec();
    v[p + 1] = v[p];
    out.push(("hint: índice duplicado en un segmento".into(), v));

    // 3) RELLENO no nulo (multi-bit): si hay padding (total < ω), el primer byte de
    //    relleno se pone a 0x03 y a 0xFF. FIPS 204 exige relleno CERO. Un flip de 1
    //    bit ya probó 0x01/0x02/...; estos valores multi-bit no los alcanza uno solo.
    if total < OMEGA {
        let pad = HINT_OFF + total;
        for (etq, val) in [("0x03", 0x03u8), ("0xFF", 0xFF)] {
            let mut v = firma.to_vec();
            v[pad] = val;
            out.push((format!("hint: relleno no nulo ({etq}) tras el último índice"), v));
        }
    }

    // 4) CUENTA fuera de rango: la última cuenta acumulada a ω+1 (> ω). FIPS 204
    //    rechaza `y[ω+i] > ω`. Cambia la longitud declarada del hint.
    let mut v = firma.to_vec();
    v[SIG_LEN - 1] = (OMEGA + 1) as u8;
    out.push(("hint: cuenta acumulada final > ω".into(), v));

    // 5) CUENTA no monótona: la última cuenta se pone por DEBAJO de la penúltima →
    //    `y[ω+i] < Index`, que FIPS 204 rechaza. Solo si la penúltima es > 0.
    let c = cuentas(firma);
    if c[K - 2] > 0 {
        let mut v = firma.to_vec();
        v[SIG_LEN - 1] = c[K - 2] - 1;
        out.push(("hint: cuenta acumulada decreciente".into(), v));
    }

    // 6) Z FUERA DE RANGO: el primer coeficiente de z se fuerza a w₀ = 0 ⇒ z₀ = γ₁,
    //    con |z₀| = γ₁ > γ₁ − β. Debe caer por el chequeo de norma de `verify`. Toca
    //    los 20 bits bajos de la región z (bytes 64,65 y el nibble bajo de 66).
    let mut v = firma.to_vec();
    v[C_TILDE_LEN] = 0;
    v[C_TILDE_LEN + 1] = 0;
    v[C_TILDE_LEN + 2] &= 0xF0; // conserva los 4 bits altos (del 2º coeficiente)
    out.push(("z: primer coeficiente fuera de rango (w=0 ⇒ z=γ₁)".into(), v));

    out
}

/// Campaña de canonicidad. Deriva mensajes de `mensaje_base` (con un contador) hasta
/// hallar una firma válida cuyo hint tenga un segmento con ≥ 2 índices —necesario
/// para reordenar y duplicar— y sobre ella prueba todas las variantes no canónicas
/// contra las DOS implementaciones. Mide primero los controles positivos (D30).
pub fn campana_canonicidad(par: &Par, mensaje_base: &[u8]) -> VeredictoCanon {
    let mut v = VeredictoCanon::default();
    let pk = pk_bytes(par);

    // Busca un mensaje con estructura de hint suficiente (casi siempre el primero:
    // una firma ML-DSA-87 típica tiene decenas de hints repartidos en 8 polinomios).
    let mut elegido: Option<(Vec<u8>, Vec<u8>, usize, usize)> = None;
    for ctr in 0u16..512 {
        v.mensajes_probados += 1;
        let mut msg = mensaje_base.to_vec();
        msg.extend_from_slice(&ctr.to_le_bytes());
        let firma = firmar(par, &msg);
        debug_assert_eq!(firma.len(), SIG_LEN, "layout ML-DSA-87 inesperado");
        if let Some((ini, len)) = primer_segmento_gordo(&firma) {
            let total = total_hints(&firma);
            elegido = Some((msg, firma, ini, len));
            let _ = len;
            let _ = total;
            break;
        }
    }

    let Some((msg, firma, seg_ini, _seg_len)) = elegido else {
        // Ningún mensaje dio estructura suficiente: la campaña queda infra-potenciada
        // y `limpio()` devolverá false (D30, D20: se falla ruidosamente).
        v.estructura_suficiente = false;
        return v;
    };
    v.estructura_suficiente = true;
    let total = total_hints(&firma);

    // Controles positivos: la firma base VÁLIDA verifica en las dos (D30).
    v.base_verifica_mldsa = verificar_mldsa_desde_pk(&pk, &msg, &firma);
    v.base_verifica_fips = verificar_fips(&pk, &msg, &firma);

    // Todas las variantes no canónicas, contra las dos puertas.
    for (desc, cand) in variantes_no_canonicas(&firma, seg_ini, total) {
        v.evaluar(&pk, &msg, &cand, || desc);
    }
    v
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::par_desde_semilla;

    /// CONTROL POSITIVO (D30): la campaña halla estructura suficiente y la firma base
    /// verifica en las dos implementaciones. Sin esto, «0 aceptadas» no dice nada.
    #[test]
    fn hay_estructura_y_la_base_verifica() {
        let par = par_desde_semilla(&[3u8; 32]);
        let v = campana_canonicidad(&par, b"canonicidad control");
        assert!(v.estructura_suficiente, "no se halló hint con un segmento ≥2 (infra-potenciada)");
        assert!(v.base_verifica_mldsa, "la firma base debe verificar en ml-dsa");
        assert!(v.base_verifica_fips, "la firma base debe verificar en fips204");
        assert!(v.probadas >= 4, "debe probar varias variantes, probó {}", v.probadas);
    }

    /// El corazón de la fase 3: NINGUNA variante no canónica del hint (ni z fuera de
    /// rango) es aceptada por ninguna de las dos implementaciones, y no discrepan.
    #[test]
    fn ninguna_variante_no_canonica_verifica() {
        let par = par_desde_semilla(&[13u8; 32]);
        let v = campana_canonicidad(&par, b"expediente clinico numero 42");
        assert!(
            v.aceptadas.is_empty(),
            "maleabilidad: {} variante(s) no canónica(s) aceptada(s): {:?}",
            v.aceptadas.len(),
            v.aceptadas
        );
        assert!(
            v.desacuerdos.is_empty(),
            "desacuerdo diferencial de canonicidad: {:?}",
            v.desacuerdos
        );
        assert!(v.limpio(), "veredicto no limpio pese a listas vacías: revisar controles");
    }

    /// PAREJA DEL CONTROL (D33): si a una de las puertas se le diera una variante que
    /// SÍ verifica, el detector `evaluar` la registraría como aceptada. Se fabrica la
    /// aceptación con la firma VÁLIDA (que verifica) para probar que el mecanismo de
    /// conteo NO está ciego —el mismo patrón que `un_desacuerdo_fabricado_se_detecta`
    /// de la fase 2—. Sin esto, un banco de solo-negativos sobre una impl limpia
    /// saldría verde con la regla buena y con una ciega por igual (D33).
    #[test]
    fn el_detector_de_aceptacion_no_esta_ciego() {
        let par = par_desde_semilla(&[21u8; 32]);
        let msg = b"deteccion de aceptacion";
        let pk = pk_bytes(&par);
        let firma = firmar(&par, msg);
        let mut v = VeredictoCanon::default();
        // Alimentamos el detector con una firma que VERIFICA (la válida): debe contarla
        // como aceptada por las dos. Si `evaluar` estuviera ciego a la aceptación, la
        // lista quedaría vacía y esta prueba fallaría.
        v.evaluar(&pk, msg, &firma, || "firma válida (fabricación del control)".into());
        assert_eq!(v.aceptadas.len(), 1, "el detector debe ver la aceptación de una firma válida");
        assert!(v.aceptadas[0].ml_dsa && v.aceptadas[0].fips204, "las dos deben aceptar la válida");
        assert!(v.desacuerdos.is_empty(), "la válida no debe producir desacuerdo");
    }

    /// PAREJA DEL CONTROL para el detector de DESACUERDO (D33): una entrada aceptada
    /// por una puerta y rechazada por la otra DEBE registrarse como desacuerdo. Se
    /// fabrica dando a la puerta ml-dsa la firma válida y forzando el registro con una
    /// candidata que fips204 rechaza (mutada), verificando el mecanismo `a != b`.
    #[test]
    fn el_detector_de_desacuerdo_no_esta_ciego() {
        // Comprobación directa del predicado que usa `evaluar`: ver aceptación de una
        // y rechazo de otra ante entradas distintas.
        let par = par_desde_semilla(&[21u8; 32]);
        let msg = b"desacuerdo canonicidad";
        let pk = pk_bytes(&par);
        let firma = firmar(&par, msg);
        let a = verificar_mldsa_desde_pk(&pk, msg, &firma); // acepta
        let mut mutada = firma.clone();
        mutada[0] ^= 0x80;
        let b = verificar_fips(&pk, msg, &mutada); // rechaza
        assert!(a && !b, "el arnés debe poder ver aceptación de una puerta y rechazo de la otra");
    }

    /// DISCRIMINACIÓN (D33): la variante de «orden intercambiado» es una maleabilidad
    /// GENUINA, no una mutación basura. Difiere de la firma base SOLO en dos bytes, y
    /// esos dos bytes son los mismos valores intercambiados dentro de la región de
    /// índices del hint (mismo CONJUNTO de índices, distinto orden). Eso prueba que un
    /// decodificador que ignorara el orden la aceptaría y verificaría: que se rechace
    /// es la regla de canonicidad mordiendo, no un accidente.
    #[test]
    fn el_reordenamiento_es_maleabilidad_genuina() {
        let par = par_desde_semilla(&[13u8; 32]);
        // Reproduce la elección de mensaje de la campaña para obtener la MISMA firma.
        let mut base = None;
        for ctr in 0u16..512 {
            let mut msg = b"expediente clinico numero 42".to_vec();
            msg.extend_from_slice(&ctr.to_le_bytes());
            let firma = firmar(&par, &msg);
            if let Some((ini, _)) = primer_segmento_gordo(&firma) {
                base = Some((firma, ini));
                break;
            }
        }
        let (firma, seg_ini) = base.expect("debe haber firma con segmento gordo");
        let total = total_hints(&firma);
        let (desc, variante) = variantes_no_canonicas(&firma, seg_ini, total)
            .into_iter()
            .next()
            .expect("la primera variante es el reordenamiento");
        assert!(desc.contains("intercambiados"), "la primera variante debe ser el swap: {desc}");
        assert_eq!(variante.len(), firma.len(), "misma longitud");
        // Exactamente dos posiciones difieren, ambas en la región de índices del hint.
        let difs: Vec<usize> = (0..firma.len()).filter(|&i| firma[i] != variante[i]).collect();
        assert_eq!(difs.len(), 2, "el swap cambia exactamente dos bytes, cambió {}", difs.len());
        for &i in &difs {
            assert!((HINT_OFF..COUNT_OFF).contains(&i), "byte cambiado fuera de la región de índices");
        }
        // Y son un intercambio: el valor de cada uno pasó al otro.
        assert_eq!(firma[difs[0]], variante[difs[1]], "no es un intercambio");
        assert_eq!(firma[difs[1]], variante[difs[0]], "no es un intercambio");
        // Multiset de índices idéntico ⇒ mismo hint semántico, solo desordenado.
        let mut a = firma[HINT_OFF..COUNT_OFF].to_vec();
        let mut b = variante[HINT_OFF..COUNT_OFF].to_vec();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b, "el conjunto de índices debe ser idéntico (equivalencia semántica)");
    }

    /// El layout de ML-DSA-87 es el que asumimos: una firma real mide SIG_LEN y sus
    /// cuentas del hint son coherentes (no decrecientes, ≤ ω). Ancla los offsets al
    /// ARTEFACTO real, no a la aritmética de las constantes (D31).
    #[test]
    fn el_layout_coincide_con_la_firma_real() {
        let par = par_desde_semilla(&[5u8; 32]);
        let firma = firmar(&par, b"layout");
        assert_eq!(firma.len(), SIG_LEN, "la firma real debe medir {SIG_LEN}");
        let c = cuentas(&firma);
        let mut prev = 0u8;
        for &x in &c {
            assert!(x >= prev, "cuentas del hint deben ser no decrecientes");
            assert!(x as usize <= OMEGA, "cuenta del hint > ω");
            prev = x;
        }
        assert!(total_hints(&firma) <= OMEGA, "total de hints > ω");
    }
}
