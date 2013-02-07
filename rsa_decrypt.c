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

int main( int argc, char *argv[] )
{
	printf("[i] Debut\n");
	if(argc != 2)
	{
		printf("Usage: %s <fichier in> <fichier out>\n", argv[0]);
		printf("Structure du fichier: <Cryptogramme (%d) (camellia (32) + sha512(64) + IV (16)) ><Fichier>\n", RSA_TAILLE/8);
		return 0;
	}
	unsigned char *fichier = NULL, *fichier_dechiffre = NULL;
	FILE *p_fichier = NULL, *sortie = NULL;
	camellia_context camellia;
	unsigned int taille;
	
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
	} 	
	printf("[i] Allocation de memoire pour les fichiers\n");
	fichier = malloc(taille * sizeof(unsigned char));//On genere le fichier  
	fichier_dechiffre = malloc((taille - RSA_TAILLE/8) * sizeof(unsigned char));
	if(fichier == NULL || fichier_dechiffre == NULL)
	{
		printf("[-] Erreur d'allocation : %d octet(s)\n", taille * sizeof(unsigned char));
		return -1;
	}
	printf("[i] Lecture du fichier\n");
	fread(fichier, taille, 1, p_fichier);
	//TODO Associer à dechiffrer
}

void dechiffrer(unsigned char *fichier_chiffre, int taille)
{
	unsigned char *clee_symetrique = NULL;
	unsigned char *IV = NULL;
	unsigned char *hash_origine = NULL;
	unsigned char hash_claire[TAILLE_HASH/8] = {0};
	unsigned char *cryptogramme_rsa = NULL;
	unsigned char data_dechiffre[TAILLE_CLEE_RSA/8] = {0};
	unsigned char *fichier = fichier_chiffre + TAILLE_CLEE_RSA/8;
	camellia_context camellia;
	//Allouer un tableau de taille- cryptogramme RSA pour le fichier clair
	unsigned char *fichier_claire = malloc(sizeof(unsigned char) * (taille - RSA_TAILLE/8));
	//recuperer cryptogramme clee camellia
	
	//dechiffrer clee camellia
	
	//Extrait les données du texte claire
	clee_symetrique = data_dechiffre;
	hash_origine = data_dechiffre + TAILLE_CLEE_CAMELIA/8;
	IV = data_dechiffre + TAILLE_CLEE_CAMELIA/8 + TAILLE_HASH/8;

	//dechiffrer fichier
	camellia_setkey_dec( &camellia, clee_symetrique, TAILLE_CLEE_CAMELIA);
	camellia_crypt_cbc( &camellia, CAMELLIA_DECRYPT, taille, IV, fichier, fichier_claire);
	
	//calculer hash  du fichier claire
	
	//comparer les hashs
}
