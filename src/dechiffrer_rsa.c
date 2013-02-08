#include <string.h>
#include <stdio.h>
#include <time.h>

#include "config.h"
#include "config_polarssl.h"
#include "rsa.h"
#include "clee_priv.h"
#include "entropy.h"
#include "ctr_drbg.h"

int dechiffrer_rsa(char* cryptogramme, int taille_cryptogramme, char* sortie, int taille_sortie)
{
	rsa_context rsa;
	char erreur;
	//On initialise le contexte RSA
	rsa_init( &rsa, RSA_PKCS_V15, 0 );
	//Initialiser les valeurs des clee
	erreur = mpi_read_string( &rsa.N, RSA_N_BASE, RSA_N);
	if(erreur != 0)
	{
		return ERREUR;
	}
	erreur = mpi_read_string( &rsa.D, RSA_D_BASE, RSA_D);
	if(erreur != 0)
	{
		return ERREUR;
	}
	//On verifie les clee
	rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;
	if(taille_cryptogramme != rsa.len)
	{
		return ERREUR;
	}
	//On dechiffre le cryptogramme
	erreur = rsa_pkcs1_decrypt( &rsa, RSA_PRIVATE, &taille_cryptogramme, cryptogramme, sortie, taille_sortie );
	if(erreur != 0)
	{
		return ERREUR;
	}
	printf("[i] Taille crypto : %d\n", taille_cryptogramme);
	return SUCCES;
}

