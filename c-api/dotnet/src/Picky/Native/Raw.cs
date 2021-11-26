using System.Runtime.InteropServices;

namespace Devolutions.Picky.Native
{
    public static unsafe partial class Raw
    {
        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_clear_last_error", ExactSpelling = true)]
        public static extern void clear_last_error();

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_last_error_length_utf8", ExactSpelling = true)]
        public static extern int last_error_length_utf8();

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_last_error_length_utf16", ExactSpelling = true)]
        public static extern int last_error_length_utf16();

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_error_message_utf8", ExactSpelling = true)]
        public static extern int error_message_utf8([NativeTypeName("char *")] sbyte* buf, int buf_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_error_message_utf16", ExactSpelling = true)]
        public static extern int error_message_utf16([NativeTypeName("uint16_t *")] ushort* buf, int buf_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_parse", ExactSpelling = true)]
        [return: NativeTypeName("struct picky_pem_t *")]
        public static extern picky_pem_t* pem_parse([NativeTypeName("const char *")] sbyte* input, int input_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_new", ExactSpelling = true)]
        [return: NativeTypeName("struct picky_pem_t *")]
        public static extern picky_pem_t* pem_new([NativeTypeName("const char *")] sbyte* label, int label_sz, [NativeTypeName("const uint8_t *")] byte* data, int data_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_encode_pem", ExactSpelling = true)]
        [return: NativeTypeName("enum picky_status_t")]
        public static extern picky_status_t encode_pem([NativeTypeName("const uint8_t *")] byte* data, int data_sz, [NativeTypeName("const char *")] sbyte* label, int label_sz, [NativeTypeName("char *")] sbyte* repr, int repr_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_data_length", ExactSpelling = true)]
        public static extern int pem_data_length([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* this_);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_data", ExactSpelling = true)]
        public static extern int pem_data([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* this_, [NativeTypeName("uint8_t *")] byte* data, int data_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_label_length", ExactSpelling = true)]
        public static extern int pem_label_length([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* this_);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_label", ExactSpelling = true)]
        public static extern int pem_label([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* this_, [NativeTypeName("char *")] sbyte* label, int label_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_compute_repr_length", ExactSpelling = true)]
        public static extern int pem_compute_repr_length([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* this_);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_to_repr", ExactSpelling = true)]
        public static extern int pem_to_repr([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* this_, [NativeTypeName("char *")] sbyte* repr, int repr_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_drop", ExactSpelling = true)]
        public static extern void pem_drop([NativeTypeName("struct picky_pem_t *")] picky_pem_t* param0);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_pem_clone", ExactSpelling = true)]
        [return: NativeTypeName("struct picky_pem_t *")]
        public static extern picky_pem_t* pem_clone([NativeTypeName("const struct picky_pem_t *")] picky_pem_t* src);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_digest", ExactSpelling = true)]
        [return: NativeTypeName("enum picky_status_t")]
        public static extern picky_status_t digest([NativeTypeName("picky_hash_algorithm_t")] int algorithm, [NativeTypeName("const uint8_t *")] byte* input, int input_sz, [NativeTypeName("uint8_t *")] byte* digest, int digest_sz);

        [DllImport("picky", CallingConvention = CallingConvention.Cdecl, EntryPoint = "picky_digest_length", ExactSpelling = true)]
        public static extern int digest_length([NativeTypeName("picky_hash_algorithm_t")] int algorithm);

        [NativeTypeName("#define PICKY_HASH_MD5 0")]
        public const int PICKY_HASH_MD5 = 0;

        [NativeTypeName("#define PICKY_HASH_SHA1 1")]
        public const int PICKY_HASH_SHA1 = 1;

        [NativeTypeName("#define PICKY_HASH_SHA2_224 2")]
        public const int PICKY_HASH_SHA2_224 = 2;

        [NativeTypeName("#define PICKY_HASH_SHA2_256 3")]
        public const int PICKY_HASH_SHA2_256 = 3;

        [NativeTypeName("#define PICKY_HASH_SHA2_384 4")]
        public const int PICKY_HASH_SHA2_384 = 4;

        [NativeTypeName("#define PICKY_HASH_SHA2_512 5")]
        public const int PICKY_HASH_SHA2_512 = 5;

        [NativeTypeName("#define PICKY_HASH_SHA3_384 6")]
        public const int PICKY_HASH_SHA3_384 = 6;

        [NativeTypeName("#define PICKY_HASH_SHA3_512 7")]
        public const int PICKY_HASH_SHA3_512 = 7;
    }
}