using System.Runtime.InteropServices;
using Xunit;

namespace Devolutions.Picky.Native.UnitTests
{
    /// <summary>Provides validation of the <see cref="picky_pem_t" /> struct.</summary>
    public static unsafe partial class picky_pem_tTests
    {
        /// <summary>Validates that the <see cref="picky_pem_t" /> struct is blittable.</summary>
        [Fact]
        public static void IsBlittableTest()
        {
            Assert.Equal(sizeof(picky_pem_t), Marshal.SizeOf<picky_pem_t>());
        }

        /// <summary>Validates that the <see cref="picky_pem_t" /> struct has the right <see cref="LayoutKind" />.</summary>
        [Fact]
        public static void IsLayoutSequentialTest()
        {
            Assert.True(typeof(picky_pem_t).IsLayoutSequential);
        }

        /// <summary>Validates that the <see cref="picky_pem_t" /> struct has the correct size.</summary>
        [Fact]
        public static void SizeOfTest()
        {
            Assert.Equal(1, sizeof(picky_pem_t));
        }
    }
}
