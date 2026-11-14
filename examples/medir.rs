// SPDX-License-Identifier: MIT OR Apache-2.0
//! Medición reproducible del arnés de Iraca-2 sobre ML-DSA-87.
//! `cargo run --release --example medir`

use iraca2::{canonicidad, diferencial};

fn main() {
    let par = iraca2::par_desde_semilla(&[3u8; 32]);
    let msg = b"radiografia de torax, paciente 1024, 2005-03-11";

    // ===== FASE 1: abuso de UNA implementación (ml-dsa) =====
    // Barrido EXHAUSTIVO de un bit (salto=1): cada bit de la firma, invertido.
    let mal = iraca2::campana_malleability(&par, msg, 1);
    // Casos estructurales de abuso.
    let est = iraca2::campana_estructural(&par, msg, b"otro mensaje");

    println!("== Iraca-2 · ML-DSA-87 ==");
    println!("-- FASE 1: abuso de ml-dsa 0.1.1 (RustCrypto FIPS 204) --");
    println!(
        "malleability (barrido exhaustivo de 1 bit): {} variantes probadas, {} aceptadas indebidamente",
        mal.probadas, mal.aceptadas_indebidas
    );
    println!(
        "abuso estructural (ceros/unos/longitud/mensaje-cruzado/clave-cruzada): {} probadas, {} aceptadas",
        est.probadas, est.aceptadas_indebidas
    );
    if mal.limpio() && est.limpio() {
        println!("  VEREDICTO FASE 1: SECO — verify rechaza toda variante no canónica/mutada/ajena.");
    } else {
        println!("  VEREDICTO FASE 1: HALLAZGO");
        for h in mal.hallazgos.iter().chain(est.hallazgos.iter()) {
            println!("    - {h}");
        }
    }

    // ===== FASE 2: DIFERENCIAL entre ml-dsa y fips204 =====
    // Barrido exhaustivo de un bit (salto=1) comparando las DOS implementaciones
    // sobre exactamente los mismos bytes.
    let dif = diferencial::campana_diferencial(&par, msg, 1);

    println!("-- FASE 2: diferencial ml-dsa 0.1.1 ↔ fips204 0.4.6 (integritychain) --");
    println!(
        "cruces de control (deben ser ambos VERDE, D30): A→B (ml-dsa firma, fips204 verifica) = {}, B→A = {}",
        dif.cruce_a_b, dif.cruce_b_a
    );
    println!(
        "corpus compartido (firma válida + barrido de 1 bit + estructurales + cruzados): {} entradas comparadas, {} desacuerdos accept/reject",
        dif.probadas,
        dif.desacuerdos.len()
    );
    if dif.limpio() {
        println!(
            "  VEREDICTO FASE 2: SECO — las dos implementaciones conformes ACUERDAN en cada entrada; ningún desacuerdo explotable."
        );
    } else if !dif.cruce_a_b || !dif.cruce_b_a {
        println!(
            "  VEREDICTO FASE 2: NO CONCLUYENTE — un cruce de control falló; el «0 desacuerdos» no es creíble (D30)."
        );
    } else {
        println!("  VEREDICTO FASE 2: HALLAZGO — desacuerdo entre implementaciones conformes:");
        for d in &dif.desacuerdos {
            println!("    - {} · ml-dsa={} fips204={}", d.descripcion, d.ml_dsa, d.fips204);
        }
    }

    // ===== FASE 3: canonicidad PROFUNDA (estructura del hint + rango de z) =====
    // Muta la ESTRUCTURA decodificada de la firma —reordenar/duplicar índices del
    // hint, romper cuentas o relleno, forzar z fuera de rango— con cambios multi-byte
    // que el barrido de 1 bit de las fases 1 y 2 NO puede construir.
    let can = canonicidad::campana_canonicidad(&par, msg);

    println!("-- FASE 3: canonicidad profunda (hint c̃‖z‖h decodificado) --");
    println!(
        "estructura suficiente (D30, un segmento de hint con ≥2 índices): {} (hallada tras {} mensaje(s))",
        can.estructura_suficiente, can.mensajes_probados
    );
    println!(
        "controles positivos: firma base verifica en ml-dsa = {}, en fips204 = {}",
        can.base_verifica_mldsa, can.base_verifica_fips
    );
    println!(
        "variantes no canónicas (orden/duplicado/relleno/cuenta del hint + z fuera de rango): {} probadas, {} aceptadas por alguna, {} desacuerdos",
        can.probadas,
        can.aceptadas.len(),
        can.desacuerdos.len()
    );
    if can.limpio() {
        println!(
            "  VEREDICTO FASE 3: SECO — ninguna codificación válida-pero-no-canónica verifica; las dos implementaciones acuerdan en rechazarlas."
        );
    } else if !can.estructura_suficiente || !can.base_verifica_mldsa || !can.base_verifica_fips {
        println!(
            "  VEREDICTO FASE 3: NO CONCLUYENTE — falló un control (estructura o firma base); el «seco» no es creíble (D30)."
        );
    } else {
        println!("  VEREDICTO FASE 3: HALLAZGO — maleabilidad o desacuerdo de canonicidad:");
        for h in can.aceptadas.iter().chain(can.desacuerdos.iter()) {
            println!("    - {} · ml-dsa={} fips204={}", h.descripcion, h.ml_dsa, h.fips204);
        }
    }
}
