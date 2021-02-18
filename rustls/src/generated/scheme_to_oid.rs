match scheme {
    SignatureScheme::DILITHIUM2 => include_bytes!("data/alg-dilithium2.der"),
    SignatureScheme::DILITHIUM3 => include_bytes!("data/alg-dilithium3.der"),
    SignatureScheme::DILITHIUM5 => include_bytes!("data/alg-dilithium5.der"),
    SignatureScheme::FALCON512 => include_bytes!("data/alg-falcon512.der"),
    SignatureScheme::FALCON1024 => include_bytes!("data/alg-falcon1024.der"),
    SignatureScheme::RAINBOWICLASSIC => include_bytes!("data/alg-rainbowiclassic.der"),
    SignatureScheme::RAINBOWICIRCUMZENITHAL => include_bytes!("data/alg-rainbowicircumzenithal.der"),
    SignatureScheme::RAINBOWICOMPRESSED => include_bytes!("data/alg-rainbowicompressed.der"),
    SignatureScheme::RAINBOWIIICLASSIC => include_bytes!("data/alg-rainbowiiiclassic.der"),
    SignatureScheme::RAINBOWIIICIRCUMZENITHAL => include_bytes!("data/alg-rainbowiiicircumzenithal.der"),
    SignatureScheme::RAINBOWIIICOMPRESSED => include_bytes!("data/alg-rainbowiiicompressed.der"),
    SignatureScheme::RAINBOWVCLASSIC => include_bytes!("data/alg-rainbowvclassic.der"),
    SignatureScheme::RAINBOWVCIRCUMZENITHAL => include_bytes!("data/alg-rainbowvcircumzenithal.der"),
    SignatureScheme::RAINBOWVCOMPRESSED => include_bytes!("data/alg-rainbowvcompressed.der"),
    SignatureScheme::SPHINCSHARAKA128FSIMPLE => include_bytes!("data/alg-sphincsharaka128fsimple.der"),
    SignatureScheme::SPHINCSHARAKA128FROBUST => include_bytes!("data/alg-sphincsharaka128frobust.der"),
    SignatureScheme::SPHINCSHARAKA128SSIMPLE => include_bytes!("data/alg-sphincsharaka128ssimple.der"),
    SignatureScheme::SPHINCSHARAKA128SROBUST => include_bytes!("data/alg-sphincsharaka128srobust.der"),
    SignatureScheme::SPHINCSHARAKA192FSIMPLE => include_bytes!("data/alg-sphincsharaka192fsimple.der"),
    SignatureScheme::SPHINCSHARAKA192FROBUST => include_bytes!("data/alg-sphincsharaka192frobust.der"),
    SignatureScheme::SPHINCSHARAKA192SSIMPLE => include_bytes!("data/alg-sphincsharaka192ssimple.der"),
    SignatureScheme::SPHINCSHARAKA192SROBUST => include_bytes!("data/alg-sphincsharaka192srobust.der"),
    SignatureScheme::SPHINCSHARAKA256FSIMPLE => include_bytes!("data/alg-sphincsharaka256fsimple.der"),
    SignatureScheme::SPHINCSHARAKA256FROBUST => include_bytes!("data/alg-sphincsharaka256frobust.der"),
    SignatureScheme::SPHINCSHARAKA256SSIMPLE => include_bytes!("data/alg-sphincsharaka256ssimple.der"),
    SignatureScheme::SPHINCSHARAKA256SROBUST => include_bytes!("data/alg-sphincsharaka256srobust.der"),
    SignatureScheme::SPHINCSSHA256128FSIMPLE => include_bytes!("data/alg-sphincssha256128fsimple.der"),
    SignatureScheme::SPHINCSSHA256128FROBUST => include_bytes!("data/alg-sphincssha256128frobust.der"),
    SignatureScheme::SPHINCSSHA256128SSIMPLE => include_bytes!("data/alg-sphincssha256128ssimple.der"),
    SignatureScheme::SPHINCSSHA256128SROBUST => include_bytes!("data/alg-sphincssha256128srobust.der"),
    SignatureScheme::SPHINCSSHA256192FSIMPLE => include_bytes!("data/alg-sphincssha256192fsimple.der"),
    SignatureScheme::SPHINCSSHA256192FROBUST => include_bytes!("data/alg-sphincssha256192frobust.der"),
    SignatureScheme::SPHINCSSHA256192SSIMPLE => include_bytes!("data/alg-sphincssha256192ssimple.der"),
    SignatureScheme::SPHINCSSHA256192SROBUST => include_bytes!("data/alg-sphincssha256192srobust.der"),
    SignatureScheme::SPHINCSSHA256256FSIMPLE => include_bytes!("data/alg-sphincssha256256fsimple.der"),
    SignatureScheme::SPHINCSSHA256256FROBUST => include_bytes!("data/alg-sphincssha256256frobust.der"),
    SignatureScheme::SPHINCSSHA256256SSIMPLE => include_bytes!("data/alg-sphincssha256256ssimple.der"),
    SignatureScheme::SPHINCSSHA256256SROBUST => include_bytes!("data/alg-sphincssha256256srobust.der"),
    SignatureScheme::SPHINCSSHAKE256128FSIMPLE => include_bytes!("data/alg-sphincsshake256128fsimple.der"),
    SignatureScheme::SPHINCSSHAKE256128FROBUST => include_bytes!("data/alg-sphincsshake256128frobust.der"),
    SignatureScheme::SPHINCSSHAKE256128SSIMPLE => include_bytes!("data/alg-sphincsshake256128ssimple.der"),
    SignatureScheme::SPHINCSSHAKE256128SROBUST => include_bytes!("data/alg-sphincsshake256128srobust.der"),
    SignatureScheme::SPHINCSSHAKE256192FSIMPLE => include_bytes!("data/alg-sphincsshake256192fsimple.der"),
    SignatureScheme::SPHINCSSHAKE256192FROBUST => include_bytes!("data/alg-sphincsshake256192frobust.der"),
    SignatureScheme::SPHINCSSHAKE256192SSIMPLE => include_bytes!("data/alg-sphincsshake256192ssimple.der"),
    SignatureScheme::SPHINCSSHAKE256192SROBUST => include_bytes!("data/alg-sphincsshake256192srobust.der"),
    SignatureScheme::SPHINCSSHAKE256256FSIMPLE => include_bytes!("data/alg-sphincsshake256256fsimple.der"),
    SignatureScheme::SPHINCSSHAKE256256FROBUST => include_bytes!("data/alg-sphincsshake256256frobust.der"),
    SignatureScheme::SPHINCSSHAKE256256SSIMPLE => include_bytes!("data/alg-sphincsshake256256ssimple.der"),
    SignatureScheme::SPHINCSSHAKE256256SROBUST => include_bytes!("data/alg-sphincsshake256256srobust.der"),
    SignatureScheme::XMSS => include_bytes!("data/alg-xmss.der"),
    SignatureScheme::KEMTLS_KYBER512 => include_bytes!("data/alg-kyber512.der"),
    SignatureScheme::KEMTLS_KYBER768 => include_bytes!("data/alg-kyber768.der"),
    SignatureScheme::KEMTLS_KYBER1024 => include_bytes!("data/alg-kyber1024.der"),
    SignatureScheme::KEMTLS_MCELIECE348864 => include_bytes!("data/alg-mceliece348864.der"),
    SignatureScheme::KEMTLS_MCELIECE348864F => include_bytes!("data/alg-mceliece348864f.der"),
    SignatureScheme::KEMTLS_MCELIECE460896 => include_bytes!("data/alg-mceliece460896.der"),
    SignatureScheme::KEMTLS_MCELIECE460896F => include_bytes!("data/alg-mceliece460896f.der"),
    SignatureScheme::KEMTLS_MCELIECE6688128 => include_bytes!("data/alg-mceliece6688128.der"),
    SignatureScheme::KEMTLS_MCELIECE6688128F => include_bytes!("data/alg-mceliece6688128f.der"),
    SignatureScheme::KEMTLS_MCELIECE6960119 => include_bytes!("data/alg-mceliece6960119.der"),
    SignatureScheme::KEMTLS_MCELIECE6960119F => include_bytes!("data/alg-mceliece6960119f.der"),
    SignatureScheme::KEMTLS_MCELIECE8192128 => include_bytes!("data/alg-mceliece8192128.der"),
    SignatureScheme::KEMTLS_MCELIECE8192128F => include_bytes!("data/alg-mceliece8192128f.der"),
    SignatureScheme::KEMTLS_LIGHTSABER => include_bytes!("data/alg-lightsaber.der"),
    SignatureScheme::KEMTLS_SABER => include_bytes!("data/alg-saber.der"),
    SignatureScheme::KEMTLS_FIRESABER => include_bytes!("data/alg-firesaber.der"),
    SignatureScheme::KEMTLS_NTRUHPS2048509 => include_bytes!("data/alg-ntruhps2048509.der"),
    SignatureScheme::KEMTLS_NTRUHPS2048677 => include_bytes!("data/alg-ntruhps2048677.der"),
    SignatureScheme::KEMTLS_NTRUHPS4096821 => include_bytes!("data/alg-ntruhps4096821.der"),
    SignatureScheme::KEMTLS_NTRUHRSS701 => include_bytes!("data/alg-ntruhrss701.der"),
    SignatureScheme::KEMTLS_NTRULPR653 => include_bytes!("data/alg-ntrulpr653.der"),
    SignatureScheme::KEMTLS_NTRULPR761 => include_bytes!("data/alg-ntrulpr761.der"),
    SignatureScheme::KEMTLS_NTRULPR857 => include_bytes!("data/alg-ntrulpr857.der"),
    SignatureScheme::KEMTLS_SNTRUP653 => include_bytes!("data/alg-sntrup653.der"),
    SignatureScheme::KEMTLS_SNTRUP761 => include_bytes!("data/alg-sntrup761.der"),
    SignatureScheme::KEMTLS_SNTRUP857 => include_bytes!("data/alg-sntrup857.der"),
    SignatureScheme::KEMTLS_FRODOKEM640AES => include_bytes!("data/alg-frodokem640aes.der"),
    SignatureScheme::KEMTLS_FRODOKEM640SHAKE => include_bytes!("data/alg-frodokem640shake.der"),
    SignatureScheme::KEMTLS_FRODOKEM976AES => include_bytes!("data/alg-frodokem976aes.der"),
    SignatureScheme::KEMTLS_FRODOKEM976SHAKE => include_bytes!("data/alg-frodokem976shake.der"),
    SignatureScheme::KEMTLS_FRODOKEM1344AES => include_bytes!("data/alg-frodokem1344aes.der"),
    SignatureScheme::KEMTLS_FRODOKEM1344SHAKE => include_bytes!("data/alg-frodokem1344shake.der"),
    SignatureScheme::KEMTLS_SIKEP434 => include_bytes!("data/alg-sikep434.der"),
    SignatureScheme::KEMTLS_SIKEP434COMPRESSED => include_bytes!("data/alg-sikep434compressed.der"),
    SignatureScheme::KEMTLS_SIKEP503 => include_bytes!("data/alg-sikep503.der"),
    SignatureScheme::KEMTLS_SIKEP503COMPRESSED => include_bytes!("data/alg-sikep503compressed.der"),
    SignatureScheme::KEMTLS_SIKEP610 => include_bytes!("data/alg-sikep610.der"),
    SignatureScheme::KEMTLS_SIKEP610COMPRESSED => include_bytes!("data/alg-sikep610compressed.der"),
    SignatureScheme::KEMTLS_SIKEP751 => include_bytes!("data/alg-sikep751.der"),
    SignatureScheme::KEMTLS_SIKEP751COMPRESSED => include_bytes!("data/alg-sikep751compressed.der"),
    SignatureScheme::KEMTLS_BIKEL1FO => include_bytes!("data/alg-bikel1fo.der"),
    SignatureScheme::KEMTLS_BIKEL3FO => include_bytes!("data/alg-bikel3fo.der"),
    _ => unreachable!(),}