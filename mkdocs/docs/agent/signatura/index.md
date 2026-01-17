# Signatura Digital

## Introducció

Per tal de verificar l'autenticitat dels informes PDF generats i assegurar que no s'han modificat, **Diag Agent** incorpora un sistema de **signatura digital** professional.

## Funcionament

Quan es genera un informe PDF, l'aplicació segueix el següent procés:

1. **Generació del PDF**: Crea el document amb WeasyPrint incloent totes les seccions seleccionades
2. **Càlcul del hash**: Calcula el hash SHA-256 del document
3. **Signatura criptogràfica**: Aplica la signatura digital utilitzant el certificat de Cybershield Solutions
4. **Marca visual**: Afegeix una marca visible a la part inferior del document

## Exemple de Signatura

A continuació es mostra com apareix la signatura digital en un informe PDF generat:

![Signatura Digital en PDF](signatura.png)

## Garanties de la Signatura

La signatura digital proporciona tres garanties fonamentals:

| Garantia | Descripció |
|----------|------------|
| **Integritat** | Confirma que el document no ha estat modificat des de la seva creació |
| **Autenticitat** | Verifica que l'informe ha estat generat per Cybershield Solutions |
| **No repudi** | L'emissor no pot negar haver generat l'informe |

## Certificat Digital

El certificat s'autogenera durant la instal·lació amb la següent configuració:

```bash
# Generat per setup_diag.sh
openssl req -new -x509 \
    -key "${CERT_DIR}/cybershield.key" \
    -out "${CERT_DIR}/cybershield.crt" \
    -days 3650 \
    -subj "/C=ES/ST=Barcelona/L=Barcelona/O=Cybershield Solutions/OU=Security Audit Division/CN=Cybershield Solutions/emailAddress=security@cybershield.solutions"
```

### Fitxers Generats

| Fitxer | Ubicació | Descripció |
|--------|----------|------------|
| `cybershield.key` | `certs/` | Clau privada RSA 2048 bits (permisos 600) |
| `cybershield.crt` | `certs/` | Certificat X.509 auto-signat (10 anys) |

## Implementació Tècnica

La signatura s'implementa amb **PyHanko**, una llibreria Python per a signatures PDF conformes amb estàndards:

```python
def sign_pdf_report(pdf_bytes):
    """
    Digitally sign a PDF report using pyhanko.
    Returns signed PDF bytes or original if signing fails.
    """
    from pyhanko.sign import signers
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.general import load_cert_from_pemder
    from pyhanko.sign.fields import SigFieldSpec
    
    # Carregar certificat i clau
    cert = load_cert_from_pemder(CERT_PATH)
    key = load_private_key_from_pemder(KEY_PATH)
    
    # Crear signador
    signer = signers.SimpleSigner.load(
        key_file=KEY_PATH,
        cert_file=CERT_PATH
    )
    
    # Aplicar signatura visible
    pdf_signer = signers.PdfSigner(
        signature_meta=signers.PdfSignatureMetadata(
            field_name='CybershieldSignature',
            reason='Security Audit Report',
            location='Tortosa, Spain'
        ),
        signer=signer,
        stamp_style=stamp_style  # Marca visual
    )
    
    return pdf_signer.sign_pdf(pdf_bytes)
```

## Verificació de la Signatura

### Amb Adobe Acrobat Reader

1. Obrir el PDF signat
2. Fer clic al panell de signatures (esquerra)
3. Clic dret sobre la signatura → "Validar signatura"

### Amb eines de línia de comandes

```bash
# Verificar amb pdfsig (poppler-utils)
pdfsig -v informe_signat.pdf

# Output esperat:
# Signature #1:
#   - Signed by: Cybershield Solutions
#   - Signing Time: 2025-01-15 10:30:00
#   - Signature Validation: Signature is Valid
```

### Validació Online

Es pot verificar la signatura a:

- [Signaturit](https://www.signaturit.com/validador)
- [Adobe Acrobat Online](https://www.adobe.com/acrobat/online/pdf-editor.html)

## Estàndards Complets

La implementació compleix amb:

- **PAdES** (PDF Advanced Electronic Signatures)
- **ISO 32000-2** (PDF 2.0)
- **ETSI EN 319 142** (Baseline signatures)

!!! info "Certificats de Producció"
    Per a entorns de producció, es recomana utilitzar un certificat emès per una Autoritat de Certificació (CA) reconeguda en lloc del certificat auto-signat.
