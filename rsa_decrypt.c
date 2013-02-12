#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "src/config.h"

#include "src/rsa.h"
#include "src/entropy.h"
#include "src/ctr_drbg.h"
#include "src/usage_camellia.h"
#include "src/camellia.h"
#include "src/clee_pub.h"
#include "src/sha4.h"

unsigned char* dechiffrer(unsigned char *fichier_chiffre, int taille);

int main( int argc, char *argv[] )
{
	printf("[i] Debut\n");
	if(argc != 3)
	{
		printf("Usage: %s <fichier in> <fichier out>\n", argv[0]);
		printf("Structure du fichier: <Cryptogramme (%d) (camellia (32) + sha512(64) + IV (16)) ><Fichier>\n", RSA_TAILLE/8);
		return 0;
	}
	unsigned char *fichier = NULL, *fichier_dechiffre = NULL;
	FILE *p_fichier = NULL, *sortie = NULL;
	camellia_context camellia;
	unsigned int taille;
	unsigned char *fichier_claire = NULL;
	//On map le fichier en memoire
	printf("[i] Lecture de la taille du fichier %s\n", argv[1]);
	p_fichier = fopen(argv[1], "rb");
	if(p_fichier == NULL)
	{
		printf("[-] Erreur d'ouverture de %s\n", argv[1]);
		return -1;
	}
	printf("[i] Mesure de la taille du fichier %s\n", argv[1]);
	fseek(p_fichier, 0, SEEK_END);
	taille = ftell(p_fichier);
	rewind(p_fichier);
	if((taille - RSA_TAILLE/8)%16 != 0)
	{
		printf("[-] Erreur de taille. Pas de multiple de 16.\n");
		return -1;
	} 	
	printf("[i] Allocation de memoire pour les fichiers\n");
	fichier = malloc(taille * sizeof(unsigned char));//On genere le fichier  
	if(fichier == NULL)
	{
		printf("[-] Erreur d'allocation : %d octet(s)\n", taille * sizeof(unsigned char));
		return -1;
	}
	printf("[i] Lecture du fichier\n");
	fread(fichier, taille, 1, p_fichier);
	fclose(p_fichier);
	
	fichier_claire = dechiffrer(fichier, taille);
	if(fichier_claire != NULL)
	{
		int i;
		printf("[i] Contenu du fichier: ");
		for(i =0; i < 10; i++)
		{
			printf("%c", fichier_claire[i]);
		}
		printf("\n");
		free(fichier_claire);
	}
	free(fichier);
	printf("[i] Fin\n");
}

unsigned char* dechiffrer(unsigned char *fichier_chiffre, int taille)
{
	unsigned char *clee_symetrique = NULL;
	unsigned char *IV = NULL;
	unsigned char *hash_origine = NULL;
	unsigned char hash_claire[TAILLE_HASH/8] = {0};
	unsigned char *cryptogramme_rsa = NULL;
	unsigned char data_dechiffre[(TAILLE_CLEE_RSA/8)] = {0};
	unsigned char *fichier = fichier_chiffre + TAILLE_CLEE_RSA/8;
	unsigned char *fichier_claire = NULL;
	char ret;
	camellia_context camellia;
	//recuperer cryptogramme 
	cryptogramme_rsa = fichier_chiffre;
	
	//dechiffrer le cryptogramme
	printf("[i] Dechiffrement du cryptogramme RSA\n");
	ret = dechiffrer_rsa(cryptogramme_rsa, (TAILLE_CLEE_RSA/8), data_dechiffre, (TAILLE_CLEE_RSA/8));
	if(ret == ERREUR)
	{
		printf("[-] Le dechiffrement a pose une erreur\n");
	}	
	//Extrait les données du texte claire
	printf("[i] Association des donnees\n");
	clee_symetrique = data_dechiffre;
	hash_origine = data_dechiffre + TAILLE_CLEE_CAMELIA/8;
	IV = data_dechiffre + TAILLE_CLEE_CAMELIA/8 + TAILLE_HASH/8;

	//dechiffrer fichier
	printf("[i] Dechiffrement du fichier avec la clee symetrique\n");
	fichier_claire = malloc(sizeof(unsigned char) * (taille - RSA_TAILLE/8));
	camellia_setkey_dec( &camellia, clee_symetrique, TAILLE_CLEE_CAMELIA);
	ret = camellia_crypt_cbc( &camellia, CAMELLIA_DECRYPT, taille - TAILLE_CLEE_RSA/8, IV, fichier, fichier_claire);
	if(ret != 0)
	{
		printf("[-] Le dechiffrement a pose une erreur\n");
		free(fichier_claire);
		return NULL;
	}
	//calculer hash  du fichier claire
	printf("[i] Calcule du hash\n");
	sha4(fichier_claire, taille - TAILLE_CLEE_RSA/8, hash_claire, 0);	
	//comparer les hashs
	printf("[i] Comparaison des hash\n");
	if(memcmp(hash_origine, hash_claire, TAILLE_HASH/8) != 0)
	{
		printf("[-] Les hash ne correspondent pas\n");
		free(fichier_claire);
		return NULL;
	}
	return fichier_claire;	
}
