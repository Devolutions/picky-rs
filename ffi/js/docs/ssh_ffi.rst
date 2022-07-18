``ssh::ffi``
============

.. js:class:: SshCert

    .. js:staticfunction:: builder()

    .. js:staticfunction:: parse(repr)

        Parses string representation of a SSH Certificate.


    .. js:function:: to_repr()

        Returns the SSH Certificate string representation.


    .. js:function:: get_public_key()

    .. js:function:: get_ssh_key_type()

    .. js:function:: get_cert_type()

    .. js:function:: get_valid_after()

    .. js:function:: get_valid_before()

    .. js:function:: get_signature_key()

    .. js:function:: get_key_id()

    .. js:function:: get_comment()

.. js:class:: SshCertBuilder

    SSH Certificate Builder.


    .. js:staticfunction:: init()

    .. js:function:: set_cert_key_type(key_type)

        Required


    .. js:function:: set_key(key)

        Required


    .. js:function:: set_serial(serial)

        Optional (set to 0 by default)


    .. js:function:: set_cert_type(cert_type)

        Required


    .. js:function:: set_key_id(key_id)

        Optional


    .. js:function:: set_valid_before(valid_before)

        Required


    .. js:function:: set_valid_after(valid_after)

        Required


    .. js:function:: set_signature_key(signature_key)

        Required


    .. js:function:: set_signature_algo(signature_algo)

        Optional. RsaPkcs1v15 with SHA256 is used by default.


    .. js:function:: set_comment(comment)

        Optional


    .. js:function:: build()

.. js:class:: SshCertKeyType

    SSH key type.


.. js:class:: SshCertType

    SSH certificate type.


.. js:class:: SshPrivateKey

    SSH Private Key.


    .. js:staticfunction:: generate_rsa(bits, passphrase, comment)

        Generates a new SSH RSA Private Key.

        No passphrase is set if ``passphrase`` is empty.

        No comment is set if ``comment`` is empty.

        This is slow in debug builds.


    .. js:staticfunction:: from_pem(pem, passphrase)

        Extracts SSH Private Key from PEM object.

        No passphrase is set if ``passphrase`` is empty.


    .. js:staticfunction:: from_private_key(key)

    .. js:function:: to_pem()

        Exports the SSH Private Key into a PEM object


    .. js:function:: to_repr()

        Returns the SSH Private Key string representation.


    .. js:function:: get_cipher_name()

    .. js:function:: get_comment()

    .. js:function:: to_public_key()

        Extracts the public part of this private key


.. js:class:: SshPublicKey

    SSH Public Key.


    .. js:staticfunction:: parse(repr)

        Parses string representation of a SSH Public Key.


    .. js:function:: to_repr()

        Returns the SSH Public Key string representation.

        It is generally represented as: "(algorithm) (der for the key) (comment)" where (comment) is usually an email address.


    .. js:function:: get_comment()
