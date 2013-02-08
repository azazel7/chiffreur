#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "src/rsa.h"
#include "src/entropy.h"
#include "src/ctr_drbg.h"
#include "src/usage_camellia.h"
#include "src/camellia.h"
#include "src/clee_pub.h"
#include "src/config_polarssl.h"
#include "src/config.h"
#include "src/sha4.h"

int main( int argc, char *argv[] )
{
	printf("[i] Debut\n");
	if(argc != 3)
	{
		printf("Usage: %s <fichier in> <fichier out>\n", argv[0]);
		printf("Structure du fichier: <Cryptogramme (%d) (camellia (32) + sha512(64) + IV (16)) ><Fichier>\n", RSA_TAILLE/8);
		return 0;
	}
	int ret;
	unsigned char *IV_svg = NULL;
	unsigned char IV[TAILLE_IV/8] = {0};
	unsigned char *hash = NULL;
	unsigned char *clee = NULL;
	unsigned char achiffrer[ TAILLE_CLEE_CAMELIA/8 + TAILLE_HASH/8 + TAILLE_IV/8] = {0}; //Correspond aux données dont l'on souhaite empêcher la modification (clée camellia et md5 du fichier et IV) on a de la place, donc autant tout mettre
	unsigned char cryptogramme_clee[RSA_TAILLE/8] = {0};
	unsigned char *fichier = NULL, *fichier_chiffre = NULL;
	FILE *p_fichier = NULL, *sortie = NULL;
	camellia_context camellia;
	unsigned int taille;

	//On fait pointer les differentes données sur des portions de achiffrer
	clee = achiffrer;
	hash = achiffrer + TAILLE_CLEE_CAMELIA/8;
	IV_svg = achiffrer + TAILLE_CLEE_CAMELIA/8 + TAILLE_HASH/8;

	printf("[i] Initialisation des IV\n");
	ret = 1;
	srand(time(NULL));
	for(ret = 0; ret < TAILLE_IV/8; ret++)
	{
		IV_svg[ret] = IV[ret] = rand();
	}
	ret = 1;
	//Argument, le fichier
	//Recuperer la clee camellia pour dechiffrer la clee rsa
	//dechiffre la clee public
	
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
	
	printf("[i] Allocation de memoire pour le fichier\n");
	fichier = malloc( (taille + (16 - (taille%16))) * sizeof(unsigned char));//On genere une taille multiple de 16
	fichier_chiffre = malloc( (taille + (16 - (taille%16))) * sizeof(unsigned char));
	if(fichier == NULL || fichier_chiffre == NULL)
	{
		printf("[-] Erreur d'allocation : %d octet(s)\n", (taille + (16 - (taille%16))) * 2 * sizeof(unsigned char));
		return -1;
	}
	printf("[i] Lecture du fichier\n");
	fread(fichier, taille, 1, p_fichier);
	taille = (taille + (16 - (taille%16))); //On fixe la taille du tableau car la taille du fichier n'importe plus 

	//On génére la clee camellia
	printf("[i] Generation de la clee camellia\n");
	generer_clee(clee, TAILLE_CLEE_CAMELIA/8);

	//on calcule le hash
	printf("[i] Calcule du hash du fichier\n");
	sha4_file( argv[1], hash, 0);

	//On chiffre le contenu du fichier
	printf("[i] Chiffrement du fichier\n");
	camellia_setkey_enc( &camellia, clee, TAILLE_CLEE_CAMELIA);
	camellia_crypt_cbc( &camellia, CAMELLIA_ENCRYPT, taille, IV, fichier, fichier_chiffre);
	
	printf("[i] Liberation du fichier claire\n");
	free(fichier);
	fichier = NULL;

	//On chiffre le bloc nom modifiable
	printf("[i] Chiffrement de la clee camellia\n");
	chiffrer_rsa(achiffrer, cryptogramme_clee, TAILLE_CLEE_CAMELIA/8 + TAILLE_IV/8 + TAILLE_HASH/8); 

	//On ecrit le cryptogramme
	printf("[i] Ouverture du fichier de sortie: %s\n", argv[2]);
	sortie = fopen(argv[2], "wb");
	if(sortie == NULL)
	{
		printf("[-] Erreur d'ouverture de %s\n", argv[2]);
		return -1;
	}
	printf("[i] Ecriture du cryptogramme (clee camellia, hash, IV)\n");
	fwrite(cryptogramme_clee, RSA_TAILLE/8, 1, sortie); 

	//On ecrit le fichier chiffre
	printf("[i] Ecriture du fichier chiffre\n");
	fwrite(fichier_chiffre, taille, 1, sortie);
	
	printf("[i] Fermeture des fichiers et liberation de la memoire\n");
	free(fichier_chiffre);
	fclose(sortie);
	fclose(p_fichier);
	
	printf("[i] Fin\n");
}
