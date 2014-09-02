#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4996) //'strcpy': This function or variable may be unsafe. 
#pragma warning(disable: 4244) // '=' : conversion from 'unsigned short' to 'unsigned char', possible loss of data
#pragma warning(disable: 4018) // '<' : signed/unsigned mismatch
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif