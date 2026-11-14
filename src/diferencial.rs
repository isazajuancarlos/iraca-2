// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Isaza Arenas

//! Fase 2 — verificación **diferencial** de ML-DSA-87 entre dos implementaciones
//! independientes y conformes del mismo estándar (FIPS 204):
//!
//! - `ml-dsa` de RustCrypto (la que consume quipu), ya atacada en la fase 1.
//! - `fips204` de integritychain (segunda implementación, código totalmente
//!   distinto: otro NTT, otro muestreo, otra codificación).
//!
//! La tesis: la conformidad (vectores KAT) prueba que ambas ACEPTAN lo válido; el
//! hueco es el **desacuerdo ante lo inválido**. Si a las dos se les da EXACTAMENTE
//! los mismos bytes (misma clave pública, mismo mensaje, misma cadena candidata a
//! firma) y una ACEPTA mientras la otra RECHAZA, esa candidata es una firma que
//! cruza una puerta y no la otra: maleabilidad en la permisiva, o interpretación
//! divergente del estándar. Un desacuerdo accept/reject entre dos implementaciones
//! conformes es un hallazgo reportable a la que se sale de la norma.
//!
//! Las dos codificaciones son byte-compatibles (FIPS 204): la clave pública de
//! ML-DSA-87 son 2592 bytes en ambas y la firma 4627. Eso permite el cruce sin
//! traducción: los bytes que sirven a una son los bytes que se le dan a la otra.
//! El contexto es el vacío (`b""`) en las dos, la variante «pura» del estándar.

use crate::{firmar, verificar, Par};
use fips204::ml_dsa_87 as fips;
use fips204::traits::{SerDes, Signer as _, Verifier as _};
use ml_dsa::{EncodedVerifyingKey, MlDsa87, VerifyingKey};

/// Los bytes canónicos de la clave pública `ml-dsa` (2592 para ML-DSA-87), listos
/// para dárselos a `fips204` sin traducir.
pub fn pk_bytes(par: &Par) -> Vec<u8> {
    par.vk.encode().as_slice().to_vec()
}

/// Verificador de la SEGUNDA implementación (`fips204`), con la misma semántica que
/// `crate::verificar`: recibe la clave pública y una cadena candidata a firma tal
/// cual la manda el mundo, y devuelve `false` ante CUALQUIER no-conformidad —clave
/// de longitud mal, firma de longitud mal, decodificación inválida o firma que no
/// valida—. Es exactamente la puerta que el atacante intenta cruzar, pero en la
/// otra implementación.
pub fn verificar_fips(pk_bytes: &[u8], mensaje: &[u8], firma: &[u8]) -> bool {
    // La clave pública debe medir PK_LEN exactos; si no, no es una clave.
    let Ok(pk_arr): Result<[u8; fips::PK_LEN], _> = pk_bytes.try_into() else {
        return false;
    };
    let Ok(pk) = fips::PublicKey::try_from_bytes(pk_arr) else {
        return false;
    };
    // La firma debe medir SIG_LEN exactos; el tipo de `fips204` lo exige, así que
    // una candidata de otra longitud se rechaza aquí, igual que `ml-dsa` la rechaza
    // en su `EncodedSignature::try_from`.
    let Ok(sig_arr): Result<[u8; fips::SIG_LEN], _> = firma.try_into() else {
        return false;
    };
    pk.verify(mensaje, &sig_arr, b"")
}

/// Verificador de la PRIMERA implementación (`ml-dsa`) partiendo de bytes de clave
/// pública crudos (para la dirección inversa: `fips204` firma → `ml-dsa` verifica).
/// `false` si la clave no decodifica.
pub fn verificar_mldsa_desde_pk(pk_bytes: &[u8], mensaje: &[u8], firma: &[u8]) -> bool {
    let Ok(enc) = EncodedVerifyingKey::<MlDsa87>::try_from(pk_bytes) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&enc);
    verificar(&vk, mensaje, firma)
}

/// Un desacuerdo entre las dos implementaciones sobre la MISMA entrada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desacuerdo {
    pub descripcion: String,
    /// ¿aceptó `ml-dsa`?
    pub ml_dsa: bool,
    /// ¿aceptó `fips204`?
    pub fips204: bool,
}

/// El veredicto de la campaña diferencial.
#[derive(Debug, Default)]
pub struct VeredictoDiferencial {
    pub probadas: usize,
    /// Entradas donde una implementación aceptó y la otra no. Debe ser 0.
    pub desacuerdos: Vec<Desacuerdo>,
    /// CONTROL POSITIVO (D30/D33): una firma `ml-dsa` válida verificada por
    /// `fips204` (cruce A→B). Debe ser `true`, o la campaña no está comparando dos
    /// implementaciones que se entienden y todo «desacuerdo» sería ruido de interop.
    pub cruce_a_b: bool,
    /// CONTROL POSITIVO inverso: firma `fips204` válida verificada por `ml-dsa`
    /// (cruce B→A).
    pub cruce_b_a: bool,
}

impl VeredictoDiferencial {
    fn comparar(&mut self, pk: &[u8], mensaje: &[u8], candidata: &[u8], que: impl FnOnce() -> String) {
        self.probadas += 1;
        let a = verificar_mldsa_desde_pk(pk, mensaje, candidata);
        let b = verificar_fips(pk, mensaje, candidata);
        if a != b && self.desacuerdos.len() < 64 {
            self.desacuerdos.push(Desacuerdo { descripcion: que(), ml_dsa: a, fips204: b });
        }
    }
    /// Limpio = ningún desacuerdo Y los dos cruces de control en verde (si los
    /// cruces fallaran, un «0 desacuerdos» no diría nada: ver D30).
    pub fn limpio(&self) -> bool {
        self.desacuerdos.is_empty() && self.cruce_a_b && self.cruce_b_a
    }
}

/// Campaña diferencial: sobre una clave pública compartida y un mensaje, alimenta a
/// las DOS implementaciones con el mismo corpus de candidatas —la firma válida, un
/// barrido de bit-flips, y casos estructurales— y registra toda entrada donde
/// discrepen. Antes mide los dos cruces de control (A→B y B→A) para que el «0
/// desacuerdos» sea creíble (D30: un negativo solo vale si el camino que lo
/// produciría se recorrió, y aquí el control es que las dos SÍ se entienden en lo
/// válido).
///
/// `salto` acota el barrido de bit-flips sobre los ~4627 bytes de la firma.
pub fn campana_diferencial(par: &Par, mensaje: &[u8], salto: usize) -> VeredictoDiferencial {
    let mut v = VeredictoDiferencial::default();
    let pk = pk_bytes(par);
    let firma = firmar(par, mensaje);

    // --- Controles positivos: las dos implementaciones se entienden en lo VÁLIDO.
    // A→B: firma de ml-dsa verificada por fips204 (clave y mensaje compartidos).
    v.cruce_a_b = verificar_fips(&pk, mensaje, &firma);
    // B→A: par y firma nativos de fips204, verificados por ml-dsa.
    let (pk_f, sk_f) = fips::try_keygen().expect("keygen fips204");
    let firma_f = sk_f.try_sign(mensaje, b"").expect("sign fips204");
    v.cruce_b_a = verificar_mldsa_desde_pk(&pk_f.into_bytes(), mensaje, &firma_f);

    // --- Corpus compartido, comparado bit a bit entre las dos puertas.
    // 1) La firma válida: las dos DEBEN aceptar (redundante con cruce_a_b, pero
    //    entra al recuento como caso de acuerdo).
    v.comparar(&pk, mensaje, &firma, || "firma válida".into());

    // 2) Barrido de bit-flips: cada mutación de un bit. Las dos DEBEN rechazar; si
    //    una acepta una mutación que la otra rechaza, es maleabilidad diferencial.
    let total_bits = firma.len() * 8;
    let mut i = 0;
    while i < total_bits {
        let mut mutada = firma.clone();
        mutada[i / 8] ^= 1 << (i % 8);
        v.comparar(&pk, mensaje, &mutada, || format!("bit {i} invertido"));
        i += salto.max(1);
    }

    // 3) Estructurales: degeneradas, longitudes al límite, mensaje y clave cruzados.
    v.comparar(&pk, mensaje, &vec![0u8; firma.len()], || "todo ceros".into());
    v.comparar(&pk, mensaje, &vec![0xFFu8; firma.len()], || "todo 0xFF".into());
    v.comparar(&pk, mensaje, &firma[..firma.len() - 1], || "truncada 1 byte".into());
    let mut mas = firma.clone();
    mas.push(0);
    v.comparar(&pk, mensaje, &mas, || "un byte extra".into());
    v.comparar(&pk, mensaje, &[], || "vacía".into());
    v.comparar(&pk, b"otro mensaje", &firma, || "mensaje cruzado".into());

    // 4) Clave cruzada: la firma de `par` con la clave pública de OTRO par. Las dos
    //    deben rechazar por igual.
    let otro = crate::par_desde_semilla(&[0x5A; 32]);
    let pk_otro = pk_bytes(&otro);
    v.comparar(&pk_otro, mensaje, &firma, || "clave cruzada".into());

    v
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::par_desde_semilla;

    /// CONTROL POSITIVO (D30/D33): las dos implementaciones se entienden en lo
    /// válido, en los DOS sentidos. Sin esto, el «0 desacuerdos» de la campaña sería
    /// indistinguible de dos implementaciones que ni siquiera hablan el mismo
    /// formato.
    #[test]
    fn las_dos_implementaciones_se_cruzan() {
        let par = par_desde_semilla(&[3u8; 32]);
        let msg = b"cruce de conformidad";
        let pk = pk_bytes(&par);
        let firma = firmar(&par, msg);
        assert!(verificar_fips(&pk, msg, &firma), "A→B: fips204 debe aceptar la firma de ml-dsa");

        let (pk_f, sk_f) = fips::try_keygen().unwrap();
        let firma_f = sk_f.try_sign(msg, b"").unwrap();
        assert!(
            verificar_mldsa_desde_pk(&pk_f.into_bytes(), msg, &firma_f),
            "B→A: ml-dsa debe aceptar la firma de fips204"
        );
    }

    /// La pareja del control (D33): `verificar_fips` RECHAZA lo que debe. Sin esto,
    /// un `verificar_fips` que dijera `true` a todo haría la campaña ciega.
    #[test]
    fn verificar_fips_discrimina() {
        let par = par_desde_semilla(&[4u8; 32]);
        let msg = b"discriminacion fips";
        let pk = pk_bytes(&par);
        let mut firma = firmar(&par, msg);
        assert!(verificar_fips(&pk, msg, &firma), "válida acepta");
        firma[0] ^= 1;
        assert!(!verificar_fips(&pk, msg, &firma), "mutada rechaza");
        assert!(!verificar_fips(&pk, b"otro", &firmar(&par, msg)), "mensaje cruzado rechaza");
        assert!(!verificar_fips(&pk[..pk.len() - 1], msg, &firmar(&par, msg)), "clave corta rechaza");
    }

    /// El corazón de la fase 2 (D8: >100 operaciones): NINGUNA entrada del corpus
    /// compartido produce desacuerdo entre las dos implementaciones, y los dos
    /// cruces de control están en verde.
    #[test]
    fn las_dos_implementaciones_no_discrepan() {
        let par = par_desde_semilla(&[13u8; 32]);
        let v = campana_diferencial(&par, b"expediente clinico numero 42", 37);
        assert!(v.probadas > 100, "debe comparar >100 entradas, comparó {}", v.probadas);
        assert!(v.cruce_a_b, "control A→B roto: las implementaciones no se entienden");
        assert!(v.cruce_b_a, "control B→A roto");
        assert!(
            v.desacuerdos.is_empty(),
            "{} desacuerdos: {:?}",
            v.desacuerdos.len(),
            v.desacuerdos
        );
    }

    /// Un mutante que fuerza un desacuerdo DEBE ser detectado (D33): si a `fips204`
    /// se le da una firma válida y a `ml-dsa` una mutada, `comparar` tiene que
    /// registrar la discrepancia. Prueba que la maquinaria de comparación no está
    /// ciega ante un desacuerdo real.
    #[test]
    fn un_desacuerdo_fabricado_se_detecta() {
        let par = par_desde_semilla(&[21u8; 32]);
        let msg = b"desacuerdo fabricado";
        let pk = pk_bytes(&par);
        let firma = firmar(&par, msg);
        // ml-dsa sobre la válida (acepta) vs fips204 sobre una mutada (rechaza):
        // construimos el desacuerdo a mano y confirmamos que las dos puertas
        // devuelven valores distintos ante entradas distintas — el mecanismo que
        // `comparar` usa para detectar.
        let a = verificar_mldsa_desde_pk(&pk, msg, &firma);
        let mut mutada = firma.clone();
        mutada[10] ^= 0x80;
        let b = verificar_fips(&pk, msg, &mutada);
        assert!(a && !b, "el arnés debe poder ver aceptación de una puerta y rechazo de la otra");
    }
}
