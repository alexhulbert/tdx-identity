from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def cert_pem_to_nist256_bytes(pem_path):
    """
    Convert a PEM certificate containing a NIST P-256 public key to a 33-byte array
    The first byte is 0x02 or 0x03 (depending on y being even or odd)
    followed by the 32-byte x coordinate
    """
    # Read the PEM certificate
    with open(pem_path, 'rb') as f:
        pem_data = f.read()
    
    # Load the certificate
    cert = x509.load_pem_x509_certificate(
        pem_data,
        backend=default_backend()
    )
    
    # Get the public key
    public_key = cert.public_key()
    
    # Verify it's an EC key of the correct curve
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Certificate does not contain an EC public key")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("Certificate's public key is not on NIST P-256 curve")
    
    # Get the compressed point format
    point_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    
    # The result should be exactly 33 bytes
    assert len(point_bytes) == 33
    
    return point_bytes

bytes_array = cert_pem_to_nist256_bytes('trusted_root.pem')
print(''.join(f'{b:02x}' for b in bytes_array))
