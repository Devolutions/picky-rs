``key::ffi``
============

.. js:class:: PrivateKey

    .. js:staticfunction:: from_pem(pem)

        Extracts private key from PEM object.


    .. js:staticfunction:: from_pkcs8(pkcs8)

        Reads a private key from its PKCS8 storage.


        - Note: ``pkcs8`` should be an ArrayBuffer or TypedArray corresponding to the slice type expected by Rust.

    .. js:staticfunction:: generate_rsa(bits)

        Generates a new RSA private key.

        This is slow in debug builds.


    .. js:function:: to_pem()

        Exports the private key into a PEM object


    .. js:function:: to_public_key()

        Extracts the public part of this private key


.. js:class:: PublicKey

    .. js:staticfunction:: from_pem(pem)

        Extracts public key from PEM object.


    .. js:staticfunction:: from_der(der)

        Reads a public key from its DER encoding.


        - Note: ``der`` should be an ArrayBuffer or TypedArray corresponding to the slice type expected by Rust.

    .. js:function:: to_pem()

        Exports the public key into a PEM object

