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
        [return: NativeTypeName("enum picky_status")]
        public static extern picky_status encode_pem([NativeTypeName("const uint8_t *")] byte* data, int data_sz, [NativeTypeName("const char *")] sbyte* label, int label_sz, [NativeTypeName("char *")] sbyte* repr, int repr_sz);

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
    }
}