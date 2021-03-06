#include <string.h>
#include <stdio.h>
#include <time.h>

#include "config.h"
#include "config_polarssl.h"
#include "rsa.h"
#include "clee_priv.h"
#include "entropy.h"
#include "ctr_drbg.h"

int chiffrer_rsa(char* data, char* sortie, int taille_data )
{
    FILE *f;
    int ret;
    size_t i;
	rsa_context rsa;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    char *pers = "rsa_encrypt";
	
    printf( "[i] Seeding the random number generator\n" );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( "[-] ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( "[i] Reading private key\n" );


    rsa_init( &rsa, RSA_PKCS_V15, 0 );
    
    if( ( ret = mpi_read_string( &rsa.N, RSA_N_BASE, RSA_N ) ) != 0 ||
        ( ret = mpi_read_string( &rsa.D, RSA_D_BASE, RSA_D ) ) != 0 )
    {
        printf( "[-] mpi_read_file returned %d\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;


    /*
     * Calculate the RSA encryption of the hash.
     */
    printf( "[i] Generating the RSA encrypted value (%d/%d)\n", rsa.len, taille_data );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_encrypt( &rsa, ctr_drbg_random, &ctr_drbg,
                                   RSA_PRIVATE, taille_data,
                                   data, sortie ) ) != 0 )
    {
        printf( "[-] rsa_pkcs1_encrypt returned %d\n\n", ret );
        goto exit;
    }
    printf( "[i] Cryptogramme copie\n");

exit:
    return( ret );
}
