``pem::ffi``
============

.. js:class:: Pem

    PEM object.


    .. js:staticfunction:: new(label, data)

        Creates a PEM object with the given label and data.


        - Note: ``data`` should be an ArrayBuffer or TypedArray corresponding to the slice type expected by Rust.

    .. js:staticfunction:: load_from_file(path)

        Loads a PEM from the filesystem.


    .. js:function:: save_to_file(path)

        Saves this PEM object to the filesystem.


    .. js:staticfunction:: parse(input)

        Parses a PEM-encoded string representation.


    .. js:function:: get_data_length()

        Returns the length of the data contained by this PEM object.


    .. js:function:: get_label()

        Returns the label of this PEM object.


    .. js:function:: to_repr()

        Returns the string representation of this PEM object.

