#include <string.h>
#include <stdio.h>
#include <time.h>


#include "config.h"
#include "rsa.h"
#include "clee_pub.h"
#include "entropy.h"
#include "ctr_drbg.h"

int chiffrer_rsa(char data[32], char* sortie )
{
    FILE *f;
    int ret;
    size_t i;
	rsa_context rsa;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    char *pers = "rsa_encrypt";
	
    printf( "[i] Seeding the random number generator\n" );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( "[-] ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( "[i] Reading public key\n" );


    rsa_init( &rsa, RSA_PKCS_V15, 0 );
    
    if( ( ret = mpi_read_string( &rsa.N, RSA_N_BASE, RSA_N ) ) != 0 ||
        ( ret = mpi_read_string( &rsa.E, RSA_E_BASE, RSA_E ) ) != 0 )
    {
        printf( "[-] mpi_read_file returned %d\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    memcpy( input, data, 32);

    /*
     * Calculate the RSA encryption of the hash.
     */
    printf( "[i] Generating the RSA encrypted value\n" );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_encrypt( &rsa, ctr_drbg_random, &ctr_drbg,
                                   RSA_PUBLIC, strlen( argv[1] ),
                                   input, buf ) ) != 0 )
    {
        printf( "[-] rsa_pkcs1_encrypt returned %d\n\n", ret );
        goto exit;
    }
	memcpy( buf, sortie, 512);
    printf( "[i] Cryptogramme copie\n");

exit:
    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_ENTROPY_C &&
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */
