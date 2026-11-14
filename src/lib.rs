// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Isaza Arenas

//! Iraca-2 — verificación **adversarial y diferencial** de ML-DSA-87 (FIPS 204).
//!
//! La misma tesis que Iraca (leanSig) aplicada a la firma lattice del NIST: el
//! ecosistema ya tiene cubierta la CONFORMIDAD (vectores KAT, entradas válidas) y
//! la interop. Lo que nadie tiene como dueño es la capa ADVERSARIAL: qué hace
//! `verify` ante entradas que NO son firmas válidas —firmas mutadas, codificaciones
//! no canónicas, longitudes mal, mensajes cruzados—. Un `verify` robusto las
//! rechaza TODAS; una que acepte alguna es maleabilidad (una firma «distinta» para
//! el mismo mensaje) o algo peor.
//!
//! Objetivo de hoy: el crate `ml-dsa` de RustCrypto (el que consume quipu). Fase 2
//! (no aquí): diferencial `ml-dsa` ↔ `fips204` (segunda implementación), cazando
//! desacuerdos accept/reject.
//!
//! Todo corre contra el `sign`/`verify` **sin modificar**, por su API pública —el
//! mismo criterio de Iraca: se ataca el esquema, no una copia parcheada.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{EncodedSignature, MlDsa87, Seed, Signature, SigningKey, VerifyingKey};

pub mod canonicidad;
pub mod diferencial;

/// Un par de claves ML-DSA-87 derivado de una semilla de 32 bytes.
pub struct Par {
    pub sk: SigningKey<MlDsa87>,
    pub vk: VerifyingKey<MlDsa87>,
}

/// Deriva un par determinista de una semilla (para pruebas reproducibles).
pub fn par_desde_semilla(semilla: &[u8; 32]) -> Par {
    let s = Seed::try_from(&semilla[..]).expect("semilla de 32 bytes");
    let sk = SigningKey::<MlDsa87>::from_seed(&s);
    let vk = sk.verifying_key();
    Par { sk, vk }
}

/// Firma un mensaje y devuelve los bytes de la firma (codificación canónica).
pub fn firmar(par: &Par, mensaje: &[u8]) -> Vec<u8> {
    par.sk.sign(mensaje).encode().as_slice().to_vec()
}

/// Verifica una firma serializada como lo hace un consumidor real: decodifica y
/// verifica. `false` si la codificación no decodifica O si la firma no valida.
/// Es exactamente la puerta que un atacante intenta cruzar.
pub fn verificar(vk: &VerifyingKey<MlDsa87>, mensaje: &[u8], firma: &[u8]) -> bool {
    let Ok(enc) = EncodedSignature::<MlDsa87>::try_from(firma) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa87>::decode(&enc) else {
        return false;
    };
    vk.verify(mensaje, &sig).is_ok()
}

/// El veredicto de una campaña de abuso: cuántas variantes se probaron y cuántas
/// —que NUNCA deberían— aceptó `verify`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Veredicto {
    pub probadas: usize,
    /// Variantes NO-canónicas/mutadas/ajenas que `verify` aceptó. Debe ser 0.
    pub aceptadas_indebidas: usize,
    /// Descripción de las aceptaciones indebidas (para el informe).
    pub hallazgos: Vec<String>,
}

impl Veredicto {
    fn registrar(&mut self, acepto: bool, que: impl FnOnce() -> String) {
        self.probadas += 1;
        if acepto {
            self.aceptadas_indebidas += 1;
            if self.hallazgos.len() < 32 {
                self.hallazgos.push(que());
            }
        }
    }
    pub fn limpio(&self) -> bool {
        self.aceptadas_indebidas == 0
    }
}

/// Campaña de MALLEABILITY: sobre una firma VÁLIDA, invierte bits (barrido
/// determinista) y comprueba que `verify` rechaza cada variante mutada. Una firma
/// mutada que verifique es maleabilidad.
///
/// `pasos` controla cuántos bits se recorren (uno de cada `salto` para acotar el
/// coste sobre los ~4627 bytes de una firma ML-DSA-87).
pub fn campana_malleability(par: &Par, mensaje: &[u8], salto: usize) -> Veredicto {
    let firma = firmar(par, mensaje);
    let mut v = Veredicto::default();
    let total_bits = firma.len() * 8;
    let mut i = 0;
    while i < total_bits {
        let mut mutada = firma.clone();
        mutada[i / 8] ^= 1 << (i % 8);
        // Una mutación puede coincidir con la firma original solo si i cae en un
        // bit ya idéntico — imposible con XOR 1, así que siempre difiere.
        let acepto = verificar(&par.vk, mensaje, &mutada);
        v.registrar(acepto, || format!("bit {i} invertido → aceptada"));
        i += salto.max(1);
    }
    v
}

/// Casos ESTRUCTURALES de abuso que un `verify` robusto debe rechazar:
/// codificaciones degeneradas, longitudes mal, y mensaje cruzado.
pub fn campana_estructural(par: &Par, mensaje: &[u8], otro_mensaje: &[u8]) -> Veredicto {
    let firma = firmar(par, mensaje);
    let mut v = Veredicto::default();

    // Todo ceros / todo unos: no son firmas válidas.
    v.registrar(verificar(&par.vk, mensaje, &vec![0u8; firma.len()]), || "todo ceros".into());
    v.registrar(verificar(&par.vk, mensaje, &vec![0xFFu8; firma.len()]), || "todo 0xFF".into());

    // Longitud mal: un byte de menos, uno de más, vacía.
    v.registrar(verificar(&par.vk, mensaje, &firma[..firma.len() - 1]), || "truncada 1 byte".into());
    let mut mas = firma.clone();
    mas.push(0);
    v.registrar(verificar(&par.vk, mensaje, &mas), || "un byte extra".into());
    v.registrar(verificar(&par.vk, mensaje, &[]), || "vacía".into());

    // Mensaje cruzado: la firma de `mensaje` NO debe valer para `otro_mensaje`.
    v.registrar(verificar(&par.vk, otro_mensaje, &firma), || "mensaje cruzado".into());

    // Clave cruzada: otra clave NO debe verificar esta firma.
    let otra = par_desde_semilla(&[0x5A; 32]);
    v.registrar(verificar(&otra.vk, mensaje, &firma), || "clave cruzada".into());

    v
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// CONTROL POSITIVO (D33): una firma válida DEBE verificar. Sin esto, un
    /// arnés que diga «0 aceptadas indebidas» podría ser uno que rechaza todo.
    #[test]
    fn la_firma_valida_verifica() {
        let par = par_desde_semilla(&[7u8; 32]);
        let msg = b"expediente clinico numero 42";
        let firma = firmar(&par, msg);
        assert!(verificar(&par.vk, msg, &firma), "una firma legítima debe verificar");
    }

    /// La pareja del control (D33): una firma con UN bit cambiado NO verifica.
    #[test]
    fn un_bit_cambiado_no_verifica() {
        let par = par_desde_semilla(&[7u8; 32]);
        let msg = b"expediente clinico numero 42";
        let mut firma = firmar(&par, msg);
        firma[0] ^= 1;
        assert!(!verificar(&par.vk, msg, &firma), "un bit cambiado no debe verificar");
    }

    /// Campaña de malleability (D8: >100 operaciones): NINGUNA mutación de una
    /// firma válida debe verificar. Recorre ~1 de cada 37 bits (>1000 variantes).
    #[test]
    fn ninguna_mutacion_verifica() {
        let par = par_desde_semilla(&[9u8; 32]);
        let msg = b"otro mensaje distinto";
        let v = campana_malleability(&par, msg, 37);
        assert!(v.probadas > 100, "debe probar >100 variantes, probó {}", v.probadas);
        assert!(v.limpio(), "maleabilidad: {} aceptadas: {:?}", v.aceptadas_indebidas, v.hallazgos);
    }

    /// Los casos estructurales de abuso se rechazan todos.
    #[test]
    fn los_casos_estructurales_se_rechazan() {
        let par = par_desde_semilla(&[11u8; 32]);
        let v = campana_estructural(&par, b"mensaje A", b"mensaje B");
        assert!(v.limpio(), "abuso estructural aceptado: {:?}", v.hallazgos);
    }
}
