#include <string.h>
#include <stdio.h>
#include <time.h>

#include "src/config.h"

#include "src/rsa.h"
#include "src/entropy.h"
#include "src/ctr_drbg.h"

int chiffrer_rsa(rsa_context *rsa, char data[32], char* sortie )
{
    FILE *f;
    int ret;
    size_t i;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    char *pers = "rsa_encrypt";

	ret = 1;

	
    if( argc != 2 )
    {
        printf( "usage: rsa_encrypt <string of max 100 characters>\n" );

#if defined(_WIN32)
        printf( "\n" );
#endif

        goto exit;
    }

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0 );
    
    if( ( ret = mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    if( strlen( argv[1] ) > 100 )
    {
        printf( " Input data larger than 100 characters.\n\n" );
        goto exit;
    }

    memcpy( input, data, 32);

    /*
     * Calculate the RSA encryption of the hash.
     */
    printf( "\n  . Generating the RSA encrypted value" );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_encrypt( &rsa, ctr_drbg_random, &ctr_drbg,
                                   RSA_PUBLIC, strlen( argv[1] ),
                                   input, buf ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    if( ( f = fopen( "result-enc.txt", "wb+" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not create %s\n\n", "result-enc.txt" );
        goto exit;
    }

   // for( i = 0; i < rsa.len; i++ )
     //  fprintf( f, "%02X%s", buf[i],
       //         ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

   for( i = 0; i < rsa.len; i++ )
       fprintf( f, "%02X", buf[i]);
    fclose( f );

    printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );

exit:

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_ENTROPY_C &&
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */
