``signature::ffi``
==================

.. js:class:: SignatureAlgorithm

    .. js:staticfunction:: new_rsa_pkcs_1v15(hash_algorithm)

    .. js:function:: verify(public_key, msg, signature)

        - Note: ``msg`` should be an ArrayBuffer or TypedArray corresponding to the slice type expected by Rust.

        - Note: ``signature`` should be an ArrayBuffer or TypedArray corresponding to the slice type expected by Rust.
