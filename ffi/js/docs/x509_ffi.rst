``x509::ffi``
=============

.. js:class:: Cert

    .. js:staticfunction:: from_der(der)

        Parses a X509 certificate from its DER representation.


        - Note: ``der`` should be an ArrayBuffer or TypedArray corresponding to the slice type expected by Rust.

    .. js:staticfunction:: from_pem(pem)

        Extracts X509 certificate from PEM object.


    .. js:function:: to_pem()

        Exports the X509 certificate into a PEM object


    .. js:function:: get_ty()

    .. js:function:: get_public_key()

    .. js:function:: get_cert_type()

    .. js:function:: get_valid_not_before()

    .. js:function:: get_valid_not_after()

    .. js:function:: get_subject_key_id_hex()

    .. js:function:: get_subject_name()

    .. js:function:: get_issuer_name()

.. js:class:: CertType
